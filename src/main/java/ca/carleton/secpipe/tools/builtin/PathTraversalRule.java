package ca.carleton.secpipe.tools.builtin;

import ca.carleton.secpipe.core.Confidence;
import ca.carleton.secpipe.core.Severity;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;

import java.util.List;
import java.util.Set;

/** CWE-22: file system paths built from untrusted input without canonicalization checks. */
public class PathTraversalRule implements JavaRule {

    private static final Set<String> FILE_TYPES = Set.of(
            "File", "FileInputStream", "FileOutputStream", "FileReader", "FileWriter", "RandomAccessFile",
            "ZipFile", "JarFile");
    private static final Set<String> PATH_FACTORIES = Set.of("get", "of");
    private static final Set<String> PATH_SCOPES = Set.of("Paths", "Path");

    @Override
    public String id() {
        return "SP-JAVA-PATH";
    }

    @Override
    public String cwe() {
        return "CWE-22";
    }

    @Override
    public void check(RuleContext ctx) {
        for (ObjectCreationExpr oc : ctx.cu().findAll(ObjectCreationExpr.class)) {
            if (FILE_TYPES.contains(oc.getType().getNameAsString())) {
                evaluate(ctx, oc, oc.getArguments(), "new " + oc.getType().getNameAsString() + "(...)");
            }
        }
        for (MethodCallExpr mc : ctx.cu().findAll(MethodCallExpr.class)) {
            String scope = mc.getScope().map(Object::toString).orElse("");
            if (PATH_FACTORIES.contains(mc.getNameAsString()) && PATH_SCOPES.contains(scope)) {
                evaluate(ctx, mc, mc.getArguments(), scope + "." + mc.getNameAsString() + "(...)");
            } else if (mc.getNameAsString().equals("resolve") && mc.getArguments().size() == 1) {
                TaintTracker t = ctx.taintFor(mc);
                if (t.level(mc.getArgument(0)) == TaintLevel.REQUEST) {
                    evaluate(ctx, mc, mc.getArguments(), "Path.resolve(...)");
                }
            }
        }
    }

    private void evaluate(RuleContext ctx, Node node, List<Expression> args, String api) {
        if (args.isEmpty() || args.stream().allMatch(TaintTracker::isConstant)) return;
        TaintTracker taint = ctx.taintFor(node);
        TaintLevel level = TaintLevel.NONE;
        boolean onlyReportedPaths = true;
        for (Expression a : args) {
            TaintLevel argLevel = taint.level(a);
            level = TaintLevel.max(level, argLevel);
            if (argLevel != TaintLevel.NONE && !isPathVariable(a, taint)) onlyReportedPaths = false;
        }
        if (level == TaintLevel.NONE) return;
        // Opening a File/Path variable that was built from tainted input in this method was already reported at its construction.
        if (onlyReportedPaths) return;
        if (level == TaintLevel.PARAMETER && !ctx.fileHandlesRequests()) return;
        boolean validated = (taint.bodyContains("getCanonicalPath") || taint.bodyContains("normalize()")
                || taint.bodyContains("toRealPath")) && taint.bodyContains("startsWith");
        if (validated) return;

        Severity severity = level == TaintLevel.REQUEST ? Severity.HIGH : Severity.MEDIUM;
        Confidence confidence = level == TaintLevel.REQUEST ? Confidence.HIGH : Confidence.LOW;
        ctx.report(node, id(), cwe(), severity, confidence, "Path traversal",
                api + " uses a path derived from " + (level == TaintLevel.REQUEST ? "HTTP request input" : "a method parameter")
                        + " without a canonical-path check. Input such as '../../etc/passwd' can escape the intended directory.");
    }

    private static boolean isPathVariable(Expression arg, TaintTracker taint) {
        if (!(arg instanceof NameExpr name)) return false;
        List<Expression> values = taint.assignedValues(name.getNameAsString());
        return !values.isEmpty() && values.stream().allMatch(PathTraversalRule::isPathConstruction);
    }

    private static boolean isPathConstruction(Expression e) {
        if (e instanceof ObjectCreationExpr oc) return FILE_TYPES.contains(oc.getType().getNameAsString());
        if (e instanceof MethodCallExpr mc) {
            String scope = mc.getScope().map(Object::toString).orElse("");
            return (PATH_FACTORIES.contains(mc.getNameAsString()) && PATH_SCOPES.contains(scope))
                    || mc.getNameAsString().equals("resolve");
        }
        return false;
    }
}
