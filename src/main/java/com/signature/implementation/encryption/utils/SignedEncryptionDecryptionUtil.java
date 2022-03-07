package com.signature.implementation.encryption.utils;

import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import com.google.gson.Gson;
import com.signature.implementation.encryption.encrypt.model.EncryptPayload;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.json.JSONException;
import org.json.JSONObject;

public class SignedEncryptionDecryptionUtil {
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    public static void main(String[] args) throws Exception {
        String privateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCck63a+IEbgRfrokzfaR6FcQXmXtBaXbhBj34wKyB1MJSNd/uqx0n/2ZHXHgqwBkXrMtATN3362wZ5xisxb0TOEGowLa3Tq7NwJAPQ1628huaAr1u+gVlL4t28gOg93KiZ1jRE31KKRIYlcw6nvIpmzPq3dG8nBBAduzNX8ATJtqqDxON3CA8uXQR4Lsg474eZguewQ7pl3BwGjOWY/OZZxE4ofHDLx6dhhnO7ogIFjxcWI5r2e1/K/2T7n9FZRBJG1V+MpGHR8APtEgI/YFzjk6QHxSPNqv+etQaDrWsPYteTisdYrUMvzgn1fNSgQM7WGBrntjgjSWwxPpehn4QlAgMBAAECggEBAJdVyXDeRXM/B86w9NnucRiK0CgENh9RfBipx05pMJr0FHDTqgQ7UJOgR2yC1dOijIuydhhMx0/hyFWEqxTBtd/xT6E3VU5EI0/dD28YNw0D2eBBHUx5GsTVBnn+ofnAv5jIx4ZVzyJi7sFdfqmy+pY3wo/0UsaED8uctxhknUwT5YrSvhjpkDla5NtNEmuue82uzoepDkBbYkAHG8/jQtk6I19ckYOJ7/ifpQwrxXH3pKeAJ17wIAh4QY2pDvSlZz0z8/Mh6M6e8LyRXaZwssT//26qYZxM26odR18mepoyVcNWsqbHPiZhyRcvYkDNL3KLdDxdwnkykxAA8/SQTUECgYEAzGr/kQpAkdrhiukA3thwEMeTU0j0TC0JCfkFCqG1/TOMV0IMsKrS1E6SMyKs1RVpbotqb3LDtcusodyizYhfPtXhQlhAlCQRmwhNwTNRRrvAb8kiJIBS7GpuMdmjyEm93WNAicgBoIB0EDVoWbMWWADAU6YyPSE6iqYx5KpirfUCgYEAxBY9WsB0omtRjC6C4pJzeqq5DhxweFcWsLQwJtIVN7jQyXCAiQntFkgfFuLTIbAIVsH7vezWrbWGSHIwIAfjk9yz8l5aa1oGbE5+3nKcPBP8fXxjKjY+uyHX+5w8j0DCs944v7xJYAShlK1F5dGqcvRize3cXU0e2Q/RBMJl73ECgYAgJH71DniitpkaX5Lsd3n/mXIX+XO4eqheMhLR3iWgn7dkjRUzvliSW5xvf/dPNiOy5ycgSRpu/oyxkuDikpvvZHAcH4ZgBN/j0cVwKKKSDbmvmh/NP4RKel3DZuZy+u1o309pmtJuq2QUnGFBIYDU66FSReLGa/AplwJnY0dK9QKBgBSDXxfHWmxDXdyUYQzi1UHX6lQXlYyBT9Zcg00MXTvfEbiBFHFBoJPcJ6R1RjEYAUdSM8vCoxK5Ersxdudi6+PkCs8oH71rRZC/BXav9rgyPw/Bm34m/pkFCVtBFPTHiZbXgIhOYj6xPVYYal+Id5RfDJcOcycvkjKS/QLKc2+BAoGAdJfir8FXbMpLYlQms3Q4Eh+8Vf7ByugV40x2JC+PNtVzjY2vNCUBV7+lArZnKwIHzTtlj3hp8XSVnQo0B7QdV9VnyccNexYjw+vM0uouGQLNGpWimQlS4AQcvw10vCtqa6hnmgbLdnOC8+mdRwyb85ju5SdFVTUSru2YXoIZ4Gg=";
        String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnJOt2viBG4EX66JM32kehXEF5l7QWl24QY9+MCsgdTCUjXf7qsdJ/9mR1x4KsAZF6zLQEzd9+tsGecYrMW9EzhBqMC2t06uzcCQD0NetvIbmgK9bvoFZS+LdvIDoPdyomdY0RN9SikSGJXMOp7yKZsz6t3RvJwQQHbszV/AEybaqg8TjdwgPLl0EeC7IOO+HmYLnsEO6ZdwcBozlmPzmWcROKHxwy8enYYZzu6ICBY8XFiOa9ntfyv9k+5/RWUQSRtVfjKRh0fAD7RICP2Bc45OkB8Ujzar/nrUGg61rD2LXk4rHWK1DL84J9XzUoEDO1hga57Y4I0lsMT6XoZ+EJQIDAQAB";
        String jsonString = "{\n" + "\"testKey\": \"test\"" + "\n" + " }";
        JSONObject jsonObj = new JSONObject(jsonString);
        String kId ="147039814738jerhklejr9047398043172h";
        JSONObject values = signAndEncrypt(jsonObj, publicKey, privateKey, kId,kId);
        System.out.println("values ::   " + values.toString());
        Gson gson = new Gson();
        EncryptPayload payload = gson.fromJson(values.toString(), EncryptPayload.class);
        System.out.println(payload.toString());
        JSONObject obj = decryptAndVerify(payload, privateKey, publicKey);
        System.out.println("Signature Verified : " + obj);
        PublicKey encryptionPublicKey = getPublicKey(publicKey);
        String data = getJwsPayload(obj, encryptionPublicKey);
        JSONObject obj2 = new JSONObject(data);
        System.out.println("data :::::::" + obj2);
    }
    public static JSONObject signAndEncrypt(JSONObject jsonRequest, String encryptionPublicKeyStr,
            String signingPrivateKeyStr, String kId ,String rsaKId) throws Exception {
        PublicKey encryptionPublicKey = getPublicKey(encryptionPublicKeyStr);
        PrivateKey signingPrivateKey = getPrivateKey(signingPrivateKeyStr);
        SecretKey aesKey = generateAESKey();
        JSONObject nextRequest = new JSONObject();
        byte[] originalIV = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(originalIV);
        String signedPayloadStr = signPayloadWithPrivateKey(jsonRequest.toString(), signingPrivateKey, kId);
        JSONObject signedPayloadJson = new JSONObject();
        System.out.println(signedPayloadStr);
        String[] signedPayloadStrArr = signedPayloadStr.split("\\.");
        signedPayloadJson.accumulate("protected", signedPayloadStrArr[0]);
        signedPayloadJson.accumulate("payload", signedPayloadStrArr[1]);
        signedPayloadJson.accumulate("signature", signedPayloadStrArr[2]);
        byte[] encryptedPayloadArr = encryptPayload(signedPayloadJson.toString(), aesKey, originalIV);
        byte[] encryptedPayLoadByteArr = Arrays.copyOfRange(encryptedPayloadArr, 0,
                encryptedPayloadArr.length - (GCM_TAG_LENGTH));
        byte[] tagByteArr = Arrays.copyOfRange(encryptedPayloadArr, encryptedPayloadArr.length - (GCM_TAG_LENGTH),
                encryptedPayloadArr.length);
        String encryptedKey = encryptKey(aesKey, encryptionPublicKey);
        String encryptedPayload = Base64.getEncoder().encodeToString(encryptedPayLoadByteArr);
        String tag = Base64.getEncoder().encodeToString(tagByteArr);
        String iv = Base64.getEncoder().encodeToString(originalIV);
        JSONObject head = new JSONObject();
        head.accumulate("kid", "cb59cce2-7581-414d-bff7-6ecf132dbef1");
        head.accumulate("alg", "RSA-OAEP");
        head.accumulate("enc", "A256GCM");
        nextRequest.accumulate("encryptedKey", encryptedKey);
        nextRequest.accumulate("encryptedPayload", encryptedPayload);
        nextRequest.accumulate("aad", tag);
        nextRequest.accumulate("header", head);
        nextRequest.accumulate("iv", iv);
        nextRequest.accumulate("rsaKeyId", rsaKId);
        return nextRequest;
    }
    public static JSONObject decryptAndVerify(EncryptPayload payload, String decryptionPrivateKey,
        String publicSignatureVerificationKey) throws Exception {
        String encryptedKey = payload.getEncryptedKey();
        String iv = payload.getIv();
        String tag = payload.getTag();
        String encryptedPayload = payload.getEncryptedPayload();
        PrivateKey gdpk = getPrivateKey(decryptionPrivateKey);
        PublicKey spsvk = getPublicKey(publicSignatureVerificationKey);
        SecretKey decryptedKey = decryptSecretKey(encryptedKey, gdpk);
        byte[] byteIV = Base64.getDecoder().decode(iv);
        byte[] byteTag = Base64.getDecoder().decode(tag);
        byte[] byteEncryptedPayload = Base64.getDecoder().decode(encryptedPayload);
        int byteTagLength = byteTag.length;
        int byteEncryptedPayloadLength = byteEncryptedPayload.length;
        byte[] byteTagEncryptedPayloadArr = new byte[byteTagLength + byteEncryptedPayloadLength];
        System.arraycopy(byteEncryptedPayload, 0, byteTagEncryptedPayloadArr, 0, byteEncryptedPayloadLength);
        System.arraycopy(byteTag, 0, byteTagEncryptedPayloadArr, byteEncryptedPayloadLength, byteTagLength);
        String decryptedPayload = decryptUsingAES(byteTagEncryptedPayloadArr, byteIV, decryptedKey);
        JSONObject decryptedPayloadJson = new JSONObject(decryptedPayload);
        String compactSerialiseddecryptedPayload = decryptedPayloadJson.getString("protected") + "."
                + decryptedPayloadJson.getString("payload") + "." + decryptedPayloadJson.getString("signature");
        System.out.println("compact : " + compactSerialiseddecryptedPayload);
        if (!verifySignature(compactSerialiseddecryptedPayload, spsvk)) {
            throw new Exception("Signature not verified");
        }
        return decryptedPayloadJson;
    }
    public static SecretKey decryptSecretKey(String key, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedText = cipher.doFinal(Base64.getDecoder().decode(key.getBytes()));
        return new SecretKeySpec(decryptedText, 0, decryptedText.length, "AES");
    }
    public static String decryptUsingAES(byte[] data, byte[] byteIV, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, byteIV);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
        byte[] decryptedText = cipher.doFinal(data);
        return new String(decryptedText);
    }
    private static Boolean verifySignature(String compactSerialisation, PublicKey publicKey) {
        boolean isVerified = false;
        try {
            JsonWebSignature jws = new JsonWebSignature();
            jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT,
                    AlgorithmIdentifiers.RSA_USING_SHA256));
            jws.setCompactSerialization(compactSerialisation);
            jws.setKey(publicKey);
            isVerified = jws.verifySignature();
        } catch (JSONException | JoseException e) {
            e.printStackTrace();
        }
        return isVerified;
    }
    public static PublicKey getPublicKey(String bas64EncodedKey) throws Exception {
        byte[] data = Base64.getDecoder().decode(bas64EncodedKey.getBytes());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(new X509EncodedKeySpec(data));
    }
    private static PrivateKey getPrivateKey(String bas64EncodedKey) throws Exception {
        byte[] data = Base64.getDecoder().decode(bas64EncodedKey.getBytes());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(new PKCS8EncodedKeySpec(data));
    }
    private static SecretKey generateAESKey() {
        KeyGenerator keyGenerator;
        SecretKey key = null;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256, new SecureRandom());
            key = keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return key;
    }
    private static String encryptKey(SecretKey symmetricKey, PublicKey publicKey) {
        String encryptedKey = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] byteSymKey = symmetricKey.getEncoded();
            byte[] ekb = cipher.doFinal(byteSymKey);
            encryptedKey = Base64.getEncoder().encodeToString(ekb);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encryptedKey;
    }
    private static String signPayloadWithPrivateKey(String data, PrivateKey privateKey, String kId) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(data);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKey(privateKey);
        jws.setKeyIdHeaderValue(kId);
        String compactSerialization = jws.getCompactSerialization();
        return compactSerialization;
    }
    private static byte[] encryptPayload(String payload, SecretKey key, byte[] IV) {
        Cipher cipher = null;
        byte[] ciphertext = null;
        try {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParameterSpec = null;
            gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
            ciphertext = cipher.doFinal(payload.toString().getBytes(Charset.defaultCharset()));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ciphertext;
    }
    public static String getJwsPayload(JSONObject decryptedPayloadJson, PublicKey publicKey) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        String compactSerialiseddecryptedPayload = decryptedPayloadJson.getString("protected") + "."
                + decryptedPayloadJson.getString("payload") + "." + decryptedPayloadJson.getString("signature");
        System.out.println("compact : " + compactSerialiseddecryptedPayload);
        
        jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT,
                AlgorithmIdentifiers.RSA_USING_SHA256));
        jws.setKey(publicKey);
        jws.setCompactSerialization(compactSerialiseddecryptedPayload);
        return jws.getPayload();
    }
}
