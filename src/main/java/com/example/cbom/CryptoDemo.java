package com.example.cbom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

/**
 * CBOM Demo - intentionally uses diverse crypto primitives
 * so cdxgen / Atom can inventory them into a Cryptography BOM.
 */
public class CryptoDemo {

    public static void main(String[] args) throws Exception {
        System.out.println("=== CBOM Demo App ===");

        // 1. AES-256-GCM (JCA)
        KeyGenerator aesGen = KeyGenerator.getInstance("AES");
        aesGen.init(256, new SecureRandom());
        SecretKey aesKey = aesGen.generateKey();
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
        byte[] ct = aesCipher.doFinal("hello-cbom".getBytes(StandardCharsets.UTF_8));
        System.out.println("AES/GCM ciphertext (base64): " + Base64.getEncoder().encodeToString(ct));

        // 2. RSA-2048
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048, new SecureRandom());
        KeyPair rsaPair = rsaGen.generateKeyPair();
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, rsaPair.getPublic());
        byte[] rsaCt = rsaCipher.doFinal("secret".getBytes(StandardCharsets.UTF_8));
        System.out.println("RSA ciphertext len: " + rsaCt.length);

        // 3. SHA-256 + SHA-512 hashing
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] digest = sha256.digest("password123".getBytes(StandardCharsets.UTF_8));
        System.out.println("SHA-256: " + bytesToHex(digest));
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        System.out.println("SHA-512 len: " + sha512.digest("abc".getBytes()).length);

        // 4. HMAC-SHA256
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(aesKey);
        byte[] macBytes = hmac.doFinal("message".getBytes(StandardCharsets.UTF_8));
        System.out.println("HMAC-SHA256: " + bytesToHex(macBytes).substring(0, 32) + "...");

        // 5. BouncyCastle provider + AES via BC
        Security.addProvider(new BouncyCastleProvider());
        Cipher bcCipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        System.out.println("BouncyCastle provider loaded: " + bcCipher.getProvider().getName());

        // 6. JWT HS256 signing (uses HMAC-SHA under the hood)
        SecretKey jwtKey = Keys.secretKeyFor(io.jsonwebtoken.SignatureAlgorithm.HS256);
        String jwt = Jwts.builder()
                .subject("demo-user")
                .signWith(jwtKey)
                .compact();
        System.out.println("JWT (HS256): " + jwt.substring(0, 40) + "...");

        // 7. TLS 1.2+ context (proves TLS usage for CBOM)
        SSLContext tls = SSLContext.getInstance("TLSv1.3");
        tls.init(null, null, new SecureRandom());
        System.out.println("TLS protocol: " + tls.getProtocol());
        // Touch HttpsURLConnection to leave a static trace for Atom
        URL url = new URL("https://example.com");
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setSSLSocketFactory(tls.getSocketFactory());
        System.out.println("HTTPS connection class ready: " + conn.getClass().getSimpleName());

        System.out.println("=== Done. All crypto primitives exercised. ===");
    }

    private static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}
