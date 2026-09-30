package ca.carleton.secpipe.tools.builtin;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.CallableDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.ArrayAccessExpr;
import com.github.javaparser.ast.expr.ArrayCreationExpr;
import com.github.javaparser.ast.expr.ArrayInitializerExpr;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.CastExpr;
import com.github.javaparser.ast.expr.ConditionalExpr;
import com.github.javaparser.ast.expr.EnclosedExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.LiteralExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.expr.TextBlockLiteralExpr;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Intra-procedural taint tracking for one method or constructor. It is deliberately simple: it follows
 * local variable initializers, assignments, {@code +=} and StringBuilder appends in source order. That is
 * enough for the localized issues the MVP targets.
 */
public class TaintTracker {

    static final Set<String> SOURCE_METHODS = Set.of(
            "getParameter", "getParameterValues", "getParameterMap", "getHeader", "getHeaders",
            "getQueryString", "getPathInfo", "getRequestURI", "getRequestURL", "getCookies",
            "getInputStream", "getReader", "getPart", "getParts", "getOriginalFilename", "getSubmittedFileName",
            "nextLine");

    static final Set<String> SOURCE_ANNOTATIONS = Set.of(
            "RequestParam", "PathVariable", "RequestHeader", "RequestBody", "CookieValue", "RequestPart",
            "ModelAttribute", "PathParam", "QueryParam", "FormParam", "HeaderParam", "CookieParam", "MatrixParam");

    static final Set<String> SANITIZERS = Set.of(
            "parseInt", "parseLong", "parseDouble", "parseFloat", "parseBoolean", "valueOf", "getName",
            "escapeSql", "escapeHtml", "escapeHtml4", "escapeXml", "encodeForSQL", "encodeForHTML", "encodeForOS",
            "quote", "quoteReplacement", "size", "length", "hashCode", "isEmpty", "isBlank", "equals",
            "equalsIgnoreCase", "contains", "startsWith", "endsWith", "matches", "count", "getClass");

    private static final Set<String> BUILDER_METHODS = Set.of("append", "insert");

    private final Map<String, TaintLevel> taint = new HashMap<>();
    private final Set<String> dynamicStrings = new HashSet<>();
    private final Map<String, List<Expression>> assignedValues = new HashMap<>();
    private final String body;

    public TaintTracker(CallableDeclaration<?> callable) {
        this.body = callable == null ? "" : callable.toString();
        if (callable == null) return;
        for (Parameter p : callable.getParameters()) {
            boolean annotated = p.getAnnotations().stream()
                    .anyMatch(a -> SOURCE_ANNOTATIONS.contains(a.getName().getIdentifier()));
            String type = p.getType().asString();
            if (annotated) {
                taint.put(p.getNameAsString(), TaintLevel.REQUEST);
            } else if (type.startsWith("String") || type.equals("Object") || type.startsWith("List<String")
                    || type.equals("CharSequence") || type.equals("InputStream") || type.equals("byte[]")) {
                taint.put(p.getNameAsString(), TaintLevel.PARAMETER);
            }
        }
        // Two passes so values assigned later in loops still propagate once.
        for (int pass = 0; pass < 2; pass++) {
            callable.walk(Node.TreeTraversal.PREORDER, this::visit);
        }
    }

    private void visit(Node node) {
        if (node instanceof VariableDeclarator vd && vd.getInitializer().isPresent()) {
            Expression init = vd.getInitializer().get();
            record(vd.getNameAsString(), init, false);
        } else if (node instanceof AssignExpr ae && ae.getTarget() instanceof NameExpr target) {
            record(target.getNameAsString(), ae.getValue(), ae.getOperator() == AssignExpr.Operator.PLUS);
        } else if (node instanceof MethodCallExpr mc && BUILDER_METHODS.contains(mc.getNameAsString())) {
            rootName(mc).ifPresent(name -> mc.getArguments().forEach(arg -> record(name, arg, true)));
        }
    }

    private java.util.Optional<String> rootName(MethodCallExpr mc) {
        Expression scope = mc.getScope().orElse(null);
        while (scope instanceof MethodCallExpr inner && BUILDER_METHODS.contains(inner.getNameAsString())) {
            scope = inner.getScope().orElse(null);
        }
        return scope instanceof NameExpr n ? java.util.Optional.of(n.getNameAsString()) : java.util.Optional.empty();
    }

    private void record(String name, Expression value, boolean concatenation) {
        List<Expression> values = assignedValues.computeIfAbsent(name, k -> new ArrayList<>());
        if (!values.contains(value)) values.add(value);
        TaintLevel level = level(value);
        taint.merge(name, level, TaintLevel::max);
        if (isDynamicString(value) || (concatenation && !isConstant(value))) dynamicStrings.add(name);
    }

    /** Every value assigned to the local variable or parameter {@code name} within the callable. */
    public List<Expression> assignedValues(String name) {
        return assignedValues.getOrDefault(name, List.of());
    }

    public TaintLevel level(Expression e) {
        if (e == null || e instanceof LiteralExpr) return TaintLevel.NONE;
        if (e instanceof NameExpr n) return taint.getOrDefault(n.getNameAsString(), TaintLevel.NONE);
        if (e instanceof MethodCallExpr mc) {
            String name = mc.getNameAsString();
            boolean stringValueOf = name.equals("valueOf")
                    && mc.getScope().map(s -> s.toString().equals("String")).orElse(false);
            if (SANITIZERS.contains(name) && !stringValueOf) return TaintLevel.NONE;
            if (SOURCE_METHODS.contains(name)) return TaintLevel.REQUEST;
            TaintLevel l = mc.getScope().map(this::level).orElse(TaintLevel.NONE);
            for (Expression arg : mc.getArguments()) l = TaintLevel.max(l, level(arg));
            return l;
        }
        if (e instanceof BinaryExpr b) return TaintLevel.max(level(b.getLeft()), level(b.getRight()));
        if (e instanceof ConditionalExpr c) return TaintLevel.max(level(c.getThenExpr()), level(c.getElseExpr()));
        if (e instanceof EnclosedExpr en) return level(en.getInner());
        if (e instanceof CastExpr c) return level(c.getExpression());
        if (e instanceof ArrayAccessExpr a) return level(a.getName());
        if (e instanceof FieldAccessExpr f) return level(f.getScope());
        if (e instanceof ObjectCreationExpr oc) {
            TaintLevel l = TaintLevel.NONE;
            for (Expression arg : oc.getArguments()) l = TaintLevel.max(l, level(arg));
            return l;
        }
        if (e instanceof ArrayCreationExpr ac) return ac.getInitializer().map(this::level).orElse(TaintLevel.NONE);
        if (e instanceof ArrayInitializerExpr ai) {
            TaintLevel l = TaintLevel.NONE;
            for (Expression v : ai.getValues()) l = TaintLevel.max(l, level(v));
            return l;
        }
        return TaintLevel.NONE;
    }

    /** True if the expression builds a string at runtime from non-constant parts. */
    public boolean isDynamicString(Expression e) {
        if (e == null) return false;
        if (e instanceof EnclosedExpr en) return isDynamicString(en.getInner());
        if (e instanceof NameExpr n) return dynamicStrings.contains(n.getNameAsString());
        if (e instanceof BinaryExpr b && b.getOperator() == BinaryExpr.Operator.PLUS) {
            return !isConstant(b.getLeft()) || !isConstant(b.getRight())
                    || isDynamicString(b.getLeft()) || isDynamicString(b.getRight());
        }
        if (e instanceof MethodCallExpr mc) {
            String name = mc.getNameAsString();
            if ((name.equals("format") || name.equals("formatted") || name.equals("concat") || name.equals("join"))
                    && mc.getArguments().stream().anyMatch(a -> !isConstant(a))) {
                return true;
            }
            if (name.equals("toString") && mc.getScope().isPresent()) return isDynamicString(mc.getScope().get());
            if (BUILDER_METHODS.contains(name)) return mc.getArguments().stream().anyMatch(a -> !isConstant(a));
        }
        return false;
    }

    public static boolean isConstant(Expression e) {
        if (e instanceof LiteralExpr) return true;
        if (e instanceof EnclosedExpr en) return isConstant(en.getInner());
        if (e instanceof BinaryExpr b) return isConstant(b.getLeft()) && isConstant(b.getRight());
        if (e instanceof NameExpr n) return isConstantName(n.getNameAsString());
        if (e instanceof FieldAccessExpr f) return isConstantName(f.getNameAsString());
        if (e instanceof ArrayInitializerExpr ai) return ai.getValues().stream().allMatch(TaintTracker::isConstant);
        if (e instanceof ArrayCreationExpr ac) return ac.getInitializer().map(TaintTracker::isConstant).orElse(true);
        return false;
    }

    private static boolean isConstantName(String name) {
        return name.length() > 1 && name.equals(name.toUpperCase()) && name.chars().anyMatch(Character::isLetter);
    }

    /** All string literal text reachable from the expression, following local variables. */
    public String literalText(Expression e) {
        StringBuilder sb = new StringBuilder();
        collectLiterals(e, sb, new HashSet<>(), 0);
        return sb.toString();
    }

    private void collectLiterals(Expression e, StringBuilder sb, Set<String> seen, int depth) {
        if (e == null || depth > 6) return;
        if (e instanceof StringLiteralExpr s) {
            sb.append(s.getValue()).append(' ');
            return;
        }
        if (e instanceof TextBlockLiteralExpr t) {
            sb.append(t.getValue()).append(' ');
            return;
        }
        if (e instanceof NameExpr n) {
            String name = n.getNameAsString();
            if (seen.add(name)) {
                for (Expression v : assignedValues.getOrDefault(name, List.of())) collectLiterals(v, sb, seen, depth + 1);
            }
            return;
        }
        for (Node child : e.getChildNodes()) {
            if (child instanceof Expression ce) collectLiterals(ce, sb, seen, depth + 1);
        }
    }

    public boolean bodyContains(String text) {
        return body.contains(text);
    }
}
