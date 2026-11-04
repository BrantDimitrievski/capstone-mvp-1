package com.shop.app;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

public class BackupEncryptor {

    private static final SecureRandom RNG = new SecureRandom();

    public static byte[] encrypt(byte[] data, SecretKey key) throws Exception {
        byte[] iv = new byte[12];
        RNG.nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] enc = c.doFinal(data);
        return ByteBuffer.allocate(iv.length + enc.length).put(iv).put(enc).array();
    }
}
