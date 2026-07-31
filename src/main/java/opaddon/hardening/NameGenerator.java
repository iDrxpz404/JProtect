package opaddon.hardening;

import java.util.Random;

/**
 * Generates per-build random-looking identifiers from a seed.
 * Produces names that look like obfuscated/minified code,
 * not revealing their purpose.
 */
public final class NameGenerator {

    private NameGenerator() {}

    private static final String JAVA_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String ID_CHARS    = "Il1O0oQCG2z5SB68gq";

    /** Generate a Java-valid class name: e.g., "a1B2c" */
    public static String className(long seed) {
        return randomString(seed, JAVA_CHARS, 6, 10);
    }

    /** Generate a method name: e.g., "l1I0O" */
    public static String methodName(long seed) {
        return randomString(seed, ID_CHARS, 5, 8);
    }

    /** Generate a field name: e.g., "fQz2" */
    public static String fieldName(long seed) {
        return randomString(seed, ID_CHARS, 4, 8);
    }

    /** Generate a valid Java package name segment */
    public static String packageName(long seed) {
        return randomString(seed, "abcdefghijklmnopqrstuvwxyz", 4, 8);
    }

    private static String randomString(long seed, String chars, int minLen, int maxLen) {
        Random rng = new Random(seed);
        int len = minLen + rng.nextInt(maxLen - minLen + 1);
        StringBuilder sb = new StringBuilder(len);
        // First char must be a letter for Java identifiers
        sb.append(JAVA_CHARS.charAt(rng.nextInt(52)));
        for (int i = 1; i < len; i++) {
            sb.append(chars.charAt(rng.nextInt(chars.length())));
        }
        return sb.toString();
    }
}
