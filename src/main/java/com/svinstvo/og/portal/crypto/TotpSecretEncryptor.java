package com.svinstvo.og.portal.crypto;

import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

@Component
public class TotpSecretEncryptor {

    private static final String ALG = "AES/GCM/NoPadding";
    private static final int IV_LEN = 12;
    private static final int TAG_LEN = 128;

    private SecretKeySpec keySpec;

    @PostConstruct
    void init() {
        String raw = System.getenv("TOTP_ENCRYPTION_KEY");
        if (raw == null) raw = System.getProperty("TOTP_ENCRYPTION_KEY");
        if (raw == null) throw new IllegalStateException("TOTP_ENCRYPTION_KEY is not set");
        byte[] key = Base64.getDecoder().decode(raw.trim());
        if (key.length != 32)
            throw new IllegalStateException("TOTP_ENCRYPTION_KEY must decode to exactly 32 bytes, got " + key.length);
        keySpec = new SecretKeySpec(key, "AES");
    }

    public String encrypt(String plaintext) {
        try {
            byte[] iv = new byte[IV_LEN];
            new SecureRandom().nextBytes(iv);
            Cipher cipher = Cipher.getInstance(ALG);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new GCMParameterSpec(TAG_LEN, iv));
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes());
            byte[] out = new byte[IV_LEN + ciphertext.length];
            System.arraycopy(iv, 0, out, 0, IV_LEN);
            System.arraycopy(ciphertext, 0, out, IV_LEN, ciphertext.length);
            return Base64.getEncoder().encodeToString(out);
        } catch (Exception e) {
            throw new IllegalStateException("Encryption failed", e);
        }
    }

    public String decrypt(String encoded) {
        try {
            byte[] in = Base64.getDecoder().decode(encoded);
            byte[] iv = new byte[IV_LEN];
            System.arraycopy(in, 0, iv, 0, IV_LEN);
            byte[] ciphertext = new byte[in.length - IV_LEN];
            System.arraycopy(in, IV_LEN, ciphertext, 0, ciphertext.length);
            Cipher cipher = Cipher.getInstance(ALG);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(TAG_LEN, iv));
            return new String(cipher.doFinal(ciphertext));
        } catch (Exception e) {
            throw new IllegalStateException("Decryption failed", e);
        }
    }
}
