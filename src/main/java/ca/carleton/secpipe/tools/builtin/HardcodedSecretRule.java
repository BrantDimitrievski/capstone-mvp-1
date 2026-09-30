package ca.carleton.secpipe.tools.builtin;

import ca.carleton.secpipe.core.Confidence;
import ca.carleton.secpipe.core.Severity;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;

import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * CWE-798 (hard-coded credentials) and CWE-321 (hard-coded cryptographic key).
 */
public class HardcodedSecretRule implements JavaRule {

    private static final Pattern SECRET_NAME = Pattern.compile(
            "(?i).*(passw(or)?d|passwd|pwd|secret|api_?key|apikey|access_?key|auth_?token|token|private_?key|credential|signing_?key|jwt_?key).*");
    private static final Pattern NOT_A_SECRET_NAME = Pattern.compile(
            "(?i).*(param|field|label|header|property|prop|message|msg|pattern|regex|query|column|attr|name|path|url|"
                    + "endpoint|placeholder|prompt|hint|text|type|policy|length|min|max|expir|ttl|validity|prefix|key_?name).*");
    private static final Pattern CRYPTO_KEY_NAME = Pattern.compile(
            "(?i).*(signing|jwt|crypto|encrypt|cipher|aes|hmac|secret_?key|private_?key).*");
    private static final List<Pattern> TOKEN_PATTERNS = List.of(
            Pattern.compile("AKIA[0-9A-Z]{16}"),
            Pattern.compile("-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
            Pattern.compile("gh[pousr]_[A-Za-z0-9]{36,}"),
            Pattern.compile("xox[baprs]-[A-Za-z0-9-]{10,}"),
            Pattern.compile("sk_live_[A-Za-z0-9]{16,}"),
            Pattern.compile("AIza[0-9A-Za-z_\\-]{35}"));
    private static final Set<String> KEY_APIS = Set.of("HMAC256", "HMAC384", "HMAC512", "setSigningKey", "hmacShaKeyFor");

    @Override
    public String id() {
        return "SP-JAVA-SECRET";
    }

    @Override
    public String cwe() {
        return "CWE-798";
    }

    @Override
    public void check(RuleContext ctx) {
        for (VariableDeclarator vd : ctx.cu().findAll(VariableDeclarator.class)) {
            vd.getInitializer().ifPresent(init -> checkAssignment(ctx, vd, vd.getNameAsString(), init));
        }
        for (AssignExpr ae : ctx.cu().findAll(AssignExpr.class)) {
            String target = ae.getTarget().isNameExpr() ? ae.getTarget().asNameExpr().getNameAsString()
                    : ae.getTarget().isFieldAccessExpr() ? ae.getTarget().asFieldAccessExpr().getNameAsString() : null;
            if (target != null) checkAssignment(ctx, ae, target, ae.getValue());
        }
        for (StringLiteralExpr s : ctx.cu().findAll(StringLiteralExpr.class)) {
            for (Pattern p : TOKEN_PATTERNS) {
                if (p.matcher(s.getValue()).find()) {
                    ctx.report(s, id(), cwe(), Severity.HIGH, Confidence.HIGH, "Hard-coded credential",
                            "String literal looks like a real access token or private key. Rotate it and load it from a secret store.");
                    break;
                }
            }
        }
        for (MethodCallExpr mc : ctx.cu().findAll(MethodCallExpr.class)) {
            String name = mc.getNameAsString();
            if (name.equals("getConnection") && mc.getArguments().size() == 3) {
                ctx.constantString(mc.getArgument(2)).filter(v -> !v.isEmpty()).ifPresent(v ->
                        ctx.report(mc, id(), cwe(), Severity.HIGH, Confidence.HIGH, "Hard-coded credential",
                                "Database password is a constant in source code. Read it from configuration or a secret store."));
            } else if ((name.equals("setPassword") || name.equals("password")) && mc.getArguments().size() == 1) {
                ctx.constantString(mc.getArgument(0)).filter(v -> v.length() >= 4 && !isPlaceholder(v)).ifPresent(v ->
                        ctx.report(mc, id(), cwe(), Severity.HIGH, Confidence.MEDIUM, "Hard-coded credential",
                                "A password is set from a constant string. Read it from configuration or a secret store."));
            } else if (KEY_APIS.contains(name) && !mc.getArguments().isEmpty()) {
                Expression arg = unwrapGetBytes(mc.getArgument(0));
                if (ctx.constantString(arg).isPresent()) reportKey(ctx, mc, name + "()");
            } else if (name.equals("signWith") && mc.getArguments().size() == 2) {
                Expression arg = unwrapGetBytes(mc.getArgument(1));
                if (ctx.constantString(arg).isPresent()) reportKey(ctx, mc, "signWith()");
            }
        }
        for (ObjectCreationExpr oc : ctx.cu().findAll(ObjectCreationExpr.class)) {
            if (!oc.getType().getNameAsString().equals("SecretKeySpec") || oc.getArguments().isEmpty()) continue;
            Expression arg = unwrapGetBytes(oc.getArgument(0));
            boolean literalBytes = arg.isArrayCreationExpr() && TaintTracker.isConstant(arg);
            if (literalBytes || ctx.constantString(arg).isPresent()) reportKey(ctx, oc, "SecretKeySpec");
        }
    }

    private void reportKey(RuleContext ctx, Node node, String api) {
        ctx.report(node, "SP-JAVA-CRYPTO-KEY", "CWE-321", Severity.HIGH, Confidence.HIGH, "Hard-coded cryptographic key",
                api + " is initialized with a key that is embedded in the source code. Anyone with the code or the binary "
                        + "can forge or decrypt data. Load the key from a key store or environment secret.");
    }

    private static Expression unwrapGetBytes(Expression e) {
        if (e instanceof MethodCallExpr mc && mc.getNameAsString().equals("getBytes") && mc.getScope().isPresent()) {
            return mc.getScope().get();
        }
        if (e instanceof MethodCallExpr mc && mc.getNameAsString().equals("decode") && mc.getArguments().size() == 1) {
            return mc.getArgument(0);
        }
        return e;
    }

    private void checkAssignment(RuleContext ctx, Node node, String name, Expression value) {
        if (!(value instanceof StringLiteralExpr lit)) return;
        String v = lit.getValue();
        if (!SECRET_NAME.matcher(name).matches() || NOT_A_SECRET_NAME.matcher(name).matches()) return;
        if (v.length() < 4 || isPlaceholder(v)) return;
        String lowerValue = v.toLowerCase(Locale.ROOT);
        String lowerName = name.toLowerCase(Locale.ROOT).replace("_", "");
        if (lowerValue.matches("[a-z_.-]+") && lowerName.contains(lowerValue.replace("_", "").replace(".", "").replace("-", ""))) {
            return;
        }
        boolean key = CRYPTO_KEY_NAME.matcher(name).matches();
        String cwe = key ? "CWE-321" : cwe();
        String rule = key ? "SP-JAVA-CRYPTO-KEY" : id();
        String title = key ? "Hard-coded cryptographic key" : "Hard-coded credential";
        ctx.report(node, rule, cwe, Severity.HIGH, v.length() >= 8 ? Confidence.HIGH : Confidence.MEDIUM, title,
                "'" + name + "' is assigned a literal secret value. Secrets in source code end up in version control and "
                        + "builds; load them from environment variables or a secret manager instead.");
    }

    private static boolean isPlaceholder(String v) {
        String t = v.trim();
        return t.contains("${") || t.contains("{{") || t.startsWith("<") || t.equalsIgnoreCase("changeme_placeholder")
                || t.chars().allMatch(c -> c == '*' || c == 'x' || c == 'X');
    }
}
