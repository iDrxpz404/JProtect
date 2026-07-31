package opaddon.hardening;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * AES-256-GCM authenticated encryption for instruction blobs and strings.
 *
 * Replaces the old XOR-only cipher. Provides:
 * - Authenticated encryption (detects tampering)
 * - Per-method random IV (nonce)
 * - PBKDF2 key derivation from seed + class name
 * - 128-bit GCM authentication tag
 *
 * Format: [salt: 16 bytes][IV: 12 bytes][ciphertext + 16-byte auth tag]
 */
public final class StreamCipher {

    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128; // bits
    private static final int SALT_LENGTH = 16;
    private static final int PBKDF2_ITERATIONS = 10000;
    private static final int AES_KEY_SIZE = 256;

    private StreamCipher() {}

    /**
     * Encrypt program bytes with AES-256-GCM.
     * @return {encrypted_blob, key_bytes} where key_bytes is the raw AES key
     */
    public static EncryptResult encrypt(long seed, String className, byte[] plaintext) {
        try {
            // Derive salt from seed + class name (deterministic)
            byte[] salt = deriveSalt(seed, className);
            // Generate random IV
            byte[] iv = new byte[GCM_IV_LENGTH];
            SecureRandom rng = SecureRandom.getInstanceStrong();
            rng.nextBytes(iv);
            // Derive AES key via PBKDF2
            byte[] keyBytes = deriveKey(String.valueOf(seed), salt);
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
            // Encrypt
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
            byte[] ciphertext = cipher.doFinal(plaintext);
            // Combine: salt + IV + ciphertext (includes auth tag)
            byte[] combined = new byte[SALT_LENGTH + GCM_IV_LENGTH + ciphertext.length];
            System.arraycopy(salt, 0, combined, 0, SALT_LENGTH);
            System.arraycopy(iv, 0, combined, SALT_LENGTH, GCM_IV_LENGTH);
            System.arraycopy(ciphertext, 0, combined, SALT_LENGTH + GCM_IV_LENGTH, ciphertext.length);
            return new EncryptResult(combined, keyBytes);
        } catch (Exception e) {
            throw new RuntimeException("AES-GCM encryption failed", e);
        }
    }

    /**
     * Decrypt AES-256-GCM encrypted data. Throws on tampering.
     * @param combined [salt:16][IV:12][ciphertext+tag]
     * @param keyBytes the raw 32-byte AES key
     */
    public static byte[] decrypt(byte[] combined, byte[] keyBytes) {
        try {
            byte[] salt = new byte[SALT_LENGTH];
            byte[] iv = new byte[GCM_IV_LENGTH];
            byte[] ciphertext = new byte[combined.length - SALT_LENGTH - GCM_IV_LENGTH];
            System.arraycopy(combined, 0, salt, 0, SALT_LENGTH);
            System.arraycopy(combined, SALT_LENGTH, iv, 0, GCM_IV_LENGTH);
            System.arraycopy(combined, SALT_LENGTH + GCM_IV_LENGTH, ciphertext, 0, ciphertext.length);
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
            return cipher.doFinal(ciphertext); // throws AEADBadTagException on tamper
        } catch (javax.crypto.AEADBadTagException e) {
            throw new SecurityException("PROGRAM integrity failure: authentication tag mismatch", e);
        } catch (Exception e) {
            throw new RuntimeException("AES-GCM decryption failed", e);
        }
    }

    private static byte[] deriveSalt(long seed, String className) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            md.update(longToBytes(seed));
            md.update(className.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            byte[] hash = md.digest();
            byte[] salt = new byte[SALT_LENGTH];
            System.arraycopy(hash, 0, salt, 0, SALT_LENGTH);
            return salt;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] deriveKey(String password, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt,
                PBKDF2_ITERATIONS, AES_KEY_SIZE);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("Key derivation failed", e);
        }
    }

    private static byte[] longToBytes(long v) {
        byte[] b = new byte[8];
        for (int i = 0; i < 8; i++) b[i] = (byte)(v >>> (56 - i * 8));
        return b;
    }

    /** Result of encryption: combined blob + raw key bytes. */
    public record EncryptResult(byte[] encrypted, byte[] keyBytes) {}
}
