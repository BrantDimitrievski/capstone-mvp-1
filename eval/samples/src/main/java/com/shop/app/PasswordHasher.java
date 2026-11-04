package com.shop.app;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PasswordHasher {

    public static String hash(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] out = md.digest(password.getBytes(StandardCharsets.UTF_8));
        return String.format("%032x", new BigInteger(1, out));
    }
}
