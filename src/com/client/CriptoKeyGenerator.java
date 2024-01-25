package com.client;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;
import java.security.SecureRandom;
import javax.crypto.spec.GCMParameterSpec;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

public class CriptoKeyGenerator {
    public static final int AES_KEY_BIT_LENGTH = 256; // Must be one of {128, 192, 256}
    public static final int GCM_NONCE_LENGTH = 12; // Nonce length
    public static final int GCM_TAG_BIT_LENGTH = 128; // Must be one of {128, 120, 112, 104, 96}

    SecretKey key = null;
    byte[] nonce = null;
    GCMParameterSpec param = null;
    byte[] aad = null;

    public CriptoKeyGenerator(String pass) {
        key = getKeyFromPassword(pass);
        nonce = generateNonce();
        param = generateGCMParameter(nonce);
    }

    public CriptoKeyGenerator() {
        KeyGenerator keyGenerator = null;
        try{
            keyGenerator = KeyGenerator.getInstance("AES");
        } catch (Exception e) {
            e.printStackTrace();
        }
        keyGenerator.init(AES_KEY_BIT_LENGTH);
        key = keyGenerator.generateKey();
        nonce = new byte[GCM_NONCE_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(nonce);
        aad = "This is an additional authenticated data.".getBytes(StandardCharsets.UTF_8);
    }

    //Accessors
    public SecretKey getKey() {
        return key;
    }

    public byte[] getNonce() {
        return nonce;
    }

    public GCMParameterSpec getParam() {
        return param;
    }

    protected SecretKey getKeyFromPassword(String pass) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update(pass.getBytes(StandardCharsets.UTF_8));
            byte[] shakey = sha.digest();
            SecretKey ret = new SecretKeySpec(shakey, "AES");
            return ret;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    protected SecretKey generateRandomKey() {
        try {
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            SecretKey ret = keygen.generateKey();
            return ret;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    protected SecretKey getKeyFromBytes(byte[] src) {
        try {
            SecretKey ret = new SecretKeySpec(src, "AES");
            return ret;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    protected byte[] generateNonce() {
        try {
            byte[] ret = new byte[12];
            SecureRandom randgen = new SecureRandom();
            randgen.nextBytes(ret);
            return ret;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public GCMParameterSpec generateGCMParameter(byte[] nonce)
    {
        try {
            GCMParameterSpec ret = new GCMParameterSpec(GCM_TAG_BIT_LENGTH, nonce);
            return ret;
        }
        catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
