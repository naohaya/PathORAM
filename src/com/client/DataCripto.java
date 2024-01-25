package com.client;

import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;


public class DataCripto {
    public static final int AES_KEY_BIT_LENGTH = 256; // Must be one of {128, 192, 256}
    public static final int GCM_NONCE_LENGTH = 12; // Nonce length
    public static final int GCM_TAG_BIT_LENGTH = 128; // Must be one of {128, 120, 112, 104, 96}

    public DataCripto(){

    }

    public static byte[] encrypt(byte[] src, SecretKey key, byte[] nonce) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
            GCMParameterSpec gcmParam = new GCMParameterSpec(GCM_TAG_BIT_LENGTH, nonce);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParam);
            byte[] ret = cipher.doFinal(src);
            return ret;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] decrypt(byte[] src, SecretKey key, byte[] nonce) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
            GCMParameterSpec gcmParam = new GCMParameterSpec(GCM_TAG_BIT_LENGTH, nonce);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParam);
            byte[] ret = cipher.doFinal(src);
            return ret;

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }
}
