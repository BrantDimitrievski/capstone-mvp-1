package com.example.vulnlab;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

/** Seeded: CWE-321 hard-coded HMAC signing key (similar to JavaVulnerableLab's JwtUtil). */
public class JwtUtil {

    private static final String SECRET_KEY = "mySuperSecretJwtSigningKey123!";

    public String sign(String payload) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(SECRET_KEY.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)));
    }
}
