package ca.carleton.secpipe.tools.builtin;

import ca.carleton.secpipe.core.Confidence;
import ca.carleton.secpipe.core.Severity;
import com.github.javaparser.ast.expr.MethodCallExpr;

import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/** CWE-327 (broken crypto algorithm) and CWE-328 (weak hash). */
public class WeakCryptoRule implements JavaRule {

    private static final Set<String> WEAK_HASHES = Set.of("MD2", "MD4", "MD5", "SHA1", "SHA-1", "SHA");
    private static final Set<String> WEAK_CIPHERS = Set.of("DES", "DESEDE", "3DES", "TRIPLEDES", "RC2", "RC4", "ARCFOUR", "BLOWFISH");
    private static final Set<String> WEAK_TLS = Set.of("SSL", "SSLV2", "SSLV3", "TLSV1", "TLSV1.1");
    private static final Set<String> DIGEST_UTILS = Set.of("md5", "md5Hex", "sha1", "sha1Hex", "sha", "shaHex", "md2", "md2Hex");

    @Override
    public String id() {
        return "SP-JAVA-CRYPTO";
    }

    @Override
    public String cwe() {
        return "CWE-327";
    }

    @Override
    public void check(RuleContext ctx) {
        for (MethodCallExpr mc : ctx.cu().findAll(MethodCallExpr.class)) {
            String scope = mc.getScope().map(Object::toString).orElse("");
            String name = mc.getNameAsString();
            if (scope.equals("DigestUtils") && DIGEST_UTILS.contains(name)) {
                weakHash(ctx, mc, name.replace("Hex", "").toUpperCase(Locale.ROOT));
                continue;
            }
            if (!name.equals("getInstance") || mc.getArguments().isEmpty()) continue;
            Optional<String> algo = ctx.constantString(mc.getArgument(0));
            if (algo.isEmpty()) continue;
            String a = algo.get().toUpperCase(Locale.ROOT);
            String base = a.split("/")[0];
            switch (scope) {
                case "MessageDigest" -> {
                    if (WEAK_HASHES.contains(a)) weakHash(ctx, mc, algo.get());
                }
                case "Cipher", "KeyGenerator", "SecretKeyFactory" -> {
                    if (WEAK_CIPHERS.contains(base) || base.startsWith("PBEWITHMD5")) {
                        ctx.report(mc, id(), "CWE-327", Severity.MEDIUM, Confidence.HIGH, "Broken or risky cryptographic algorithm",
                                "'" + algo.get() + "' is a broken or deprecated cipher. Use AES/GCM/NoPadding with a 256-bit key.");
                    } else if (scope.equals("Cipher") && (a.contains("/ECB/") || a.equals("AES"))) {
                        ctx.report(mc, id(), "CWE-327", Severity.MEDIUM, Confidence.MEDIUM, "Insecure cipher mode (ECB)",
                                "'" + algo.get() + "' uses ECB mode" + (a.equals("AES") ? " by default" : "")
                                        + ", which leaks patterns in the plaintext. Use AES/GCM/NoPadding with a random IV.");
                    }
                }
                case "SSLContext" -> {
                    if (WEAK_TLS.contains(a)) {
                        ctx.report(mc, id(), "CWE-327", Severity.MEDIUM, Confidence.HIGH, "Deprecated TLS/SSL protocol",
                                "'" + algo.get() + "' enables obsolete protocol versions. Use \"TLSv1.3\" (or at least TLSv1.2).");
                    }
                }
                default -> {
                }
            }
        }
    }

    private void weakHash(RuleContext ctx, MethodCallExpr mc, String algo) {
        ctx.report(mc, "SP-JAVA-HASH", "CWE-328", Severity.MEDIUM, Confidence.HIGH, "Weak hash algorithm",
                algo + " is not collision resistant and is unsuitable for passwords or integrity checks. "
                        + "Use SHA-256 for integrity and bcrypt/scrypt/Argon2/PBKDF2 for passwords.");
    }
}
