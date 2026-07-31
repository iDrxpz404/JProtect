package opaddon.hardening;

import java.util.Random;

/**
 * Simple XOR stream cipher for encrypting/decrypting instruction blobs.
 *
 * Uses a per-class key derived from the build seed and class name.
 * The encrypted blob is decrypted once at class init time ({@code <clinit>}).
 */
public final class StreamCipher {

    private StreamCipher() {}

    /**
     * Generate a deterministic key from seed + class name.
     */
    public static byte[] generateKey(long seed, String className, int length) {
        Random rng = new Random(seed ^ className.hashCode());
        byte[] key = new byte[length];
        for (int i = 0; i < length; i++) {
            key[i] = (byte) (rng.nextInt(256) - 128);
        }
        return key;
    }

    /**
     * XOR encrypt/decrypt (symmetric).
     */
    public static void xor(byte[] data, byte[] key) {
        int klen = key.length;
        for (int i = 0; i < data.length; i++) {
            data[i] ^= key[i % klen];
        }
    }

    /**
     * Encrypt program bytes in place.
     * @return the key used (needed for decryption at runtime)
     */
    public static byte[] encrypt(long seed, String className, byte[] program) {
        byte[] key = generateKey(seed, className, program.length);
        byte[] encrypted = program.clone();
        xor(encrypted, key);
        return key;
    }

    /**
     * Apply XOR with given key to decrypt.
     */
    public static byte[] decrypt(byte[] encrypted, byte[] key) {
        byte[] decrypted = encrypted.clone();
        xor(decrypted, key);
        return decrypted;
    }
}
