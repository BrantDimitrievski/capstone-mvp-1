package ca.carleton.secpipe.tools.builtin;

import ca.carleton.secpipe.core.Severity;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;

import java.util.Set;
import java.util.regex.Pattern;

/** CWE-89: SQL/HQL built by string concatenation and passed to a query API. */
public class SqlInjectionRule implements JavaRule {

    private static final Set<String> SQL_SPECIFIC = Set.of(
            "executeQuery", "executeUpdate", "executeLargeUpdate", "prepareStatement", "prepareCall",
            "addBatch", "createQuery", "createNativeQuery", "createSQLQuery", "nativeQuery");
    private static final Set<String> GENERIC = Set.of(
            "execute", "query", "queryForObject", "queryForList", "queryForMap", "queryForRowSet", "update", "batchUpdate");
    private static final Pattern SQL = Pattern.compile(
            "(?i)\\b(select\\s|insert\\s+into|update\\s+\\w+\\s+set|delete\\s+from|\\bfrom\\s|\\bwhere\\s|order\\s+by|values\\s*\\()");

    @Override
    public String id() {
        return "SP-JAVA-SQLI";
    }

    @Override
    public String cwe() {
        return "CWE-89";
    }

    @Override
    public void check(RuleContext ctx) {
        for (MethodCallExpr call : ctx.cu().findAll(MethodCallExpr.class)) {
            String name = call.getNameAsString();
            boolean specific = SQL_SPECIFIC.contains(name);
            if ((!specific && !GENERIC.contains(name)) || call.getArguments().isEmpty()) continue;
            Expression query = call.getArgument(0);
            TaintTracker taint = ctx.taintFor(call);
            if (!taint.isDynamicString(query)) continue;
            String text = taint.literalText(query);
            if (!SQL.matcher(text).find() && !(specific && !text.isBlank())) continue;

            TaintLevel level = taint.level(query);
            Severity severity = level == TaintLevel.REQUEST ? Severity.CRITICAL : Severity.HIGH;
            String source = switch (level) {
                case REQUEST -> "HTTP request input";
                case PARAMETER -> "a method parameter";
                case NONE -> "a non-constant value";
            };
            ctx.report(call, id(), cwe(), severity, level.confidence(), "SQL injection",
                    "Query passed to " + name + "() is built by string concatenation with " + source
                            + ". An attacker can change the SQL statement. Use a PreparedStatement with ? placeholders.");
        }
    }
}
