package example;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Sample {
    void run() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC");
        ecKpg.initialize(new ECGenParameterSpec("secp256r1"));
        Signature sig = Signature.getInstance("SHA1withRSA");
        Cipher ecb = Cipher.getInstance("AES/ECB/PKCS5Padding");
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        Cipher defaultMode = Cipher.getInstance("DESede");
        MessageDigest md = MessageDigest.getInstance("MD5");
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        // Cipher.getInstance("RC4") is commented out
        /* MessageDigest.getInstance("SHA-1"); */
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        SSLContext tls = SSLContext.getInstance("TLSv1.1");
        SSLContext generic = SSLContext.getInstance("TLS");
        KeyPairGenerator pq = KeyPairGenerator.getInstance("ML-KEM-768");
    }
}
