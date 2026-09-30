package ca.carleton.secpipe.tools.builtin;

import ca.carleton.secpipe.core.Confidence;
import ca.carleton.secpipe.core.Severity;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
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
        for (Expression a : args) level = TaintLevel.max(level, taint.level(a));
        if (level == TaintLevel.NONE) return;
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
}
