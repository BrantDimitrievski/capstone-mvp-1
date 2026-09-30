package ca.carleton.secpipe.tools.builtin;

import ca.carleton.secpipe.core.Confidence;
import ca.carleton.secpipe.core.Severity;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;

import java.util.List;

/** CWE-78: OS commands built from non-constant input. */
public class CommandInjectionRule implements JavaRule {

    @Override
    public String id() {
        return "SP-JAVA-CMDI";
    }

    @Override
    public String cwe() {
        return "CWE-78";
    }

    @Override
    public void check(RuleContext ctx) {
        for (MethodCallExpr mc : ctx.cu().findAll(MethodCallExpr.class)) {
            if (!mc.getNameAsString().equals("exec")) continue;
            String scope = mc.getScope().map(Object::toString).orElse("");
            boolean runtimeVar = ctx.cu().findAll(com.github.javaparser.ast.body.VariableDeclarator.class).stream()
                    .anyMatch(vd -> vd.getNameAsString().equals(scope) && vd.getTypeAsString().equals("Runtime"));
            if (scope.contains("getRuntime()") || runtimeVar) {
                evaluate(ctx, mc, mc.getArguments(), "Runtime.exec()");
            }
        }
        for (ObjectCreationExpr oc : ctx.cu().findAll(ObjectCreationExpr.class)) {
            if (oc.getType().getNameAsString().equals("ProcessBuilder")) {
                evaluate(ctx, oc, oc.getArguments(), "new ProcessBuilder()");
            }
        }
    }

    private void evaluate(RuleContext ctx, Node node, List<Expression> args, String api) {
        if (args.isEmpty() || args.stream().allMatch(TaintTracker::isConstant)) return;
        TaintTracker taint = ctx.taintFor(node);
        TaintLevel level = TaintLevel.NONE;
        for (Expression a : args) level = TaintLevel.max(level, taint.level(a));
        boolean shell = args.stream().anyMatch(a -> a.toString().matches("(?s).*\"(/bin/)?(ba)?sh\".*|.*\"cmd(\\.exe)?\".*"));

        Severity severity = switch (level) {
            case REQUEST -> Severity.CRITICAL;
            case PARAMETER -> Severity.HIGH;
            case NONE -> Severity.MEDIUM;
        };
        Confidence confidence = level == TaintLevel.NONE ? Confidence.LOW : level.confidence();
        ctx.report(node, id(), cwe(), severity, confidence, "OS command injection",
                api + " runs a command built from " + switch (level) {
                    case REQUEST -> "HTTP request input";
                    case PARAMETER -> "a method parameter";
                    case NONE -> "a non-constant value";
                } + (shell ? " through a shell" : "")
                        + ". Validate the input against an allow-list and pass arguments as a fixed array, never via a shell.");
    }
}
