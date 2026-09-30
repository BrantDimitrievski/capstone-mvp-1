package com.example.vulnlab;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HexFormat;

/** Seeded: CWE-328 MD5 password hashing and CWE-327 DES/ECB encryption. */
public class CryptoUtil {

    public String hashPassword(String password) throws GeneralSecurityException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return HexFormat.of().formatHex(md.digest(password.getBytes(StandardCharsets.UTF_8)));
    }

    public byte[] encrypt(SecretKey key, String data) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    /** Secure alternative: must not be flagged. */
    public String checksum(byte[] data) throws GeneralSecurityException {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
    }
}
