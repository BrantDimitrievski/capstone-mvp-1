package com.shop.app;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.util.Base64;

public class ConfigEncryptor {

    public static String encrypt(String value, SecretKey key) throws Exception {
        Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(c.doFinal(value.getBytes()));
    }
}
