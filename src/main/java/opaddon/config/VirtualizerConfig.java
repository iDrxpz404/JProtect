package opaddon.config;

import java.util.*;

/**
 * JSON-configurable protection settings.
 *
 * <pre>
 * {
 *   "preset": "balanced",
 *   "seed": 0,
 *   "virtualize": ["com.example.LicenseManager.*", "com.example.Security.*"],
 *   "exclude": ["com.example.Unsafe"],
 *   "stringEncryption": true,
 *   "opcodeShuffle": false,
 *   "integrityCheck": false,
 *   "polymorphicVM": false
 * }
 * </pre>
 */
public final class VirtualizerConfig {

    private String preset = "balanced";
    private long seed;
    private List<String> virtualize = new ArrayList<>();
    private List<String> exclude = new ArrayList<>();
    private boolean stringEncryption = true;
    private boolean opcodeShuffle;
    private boolean integrityCheck;
    private boolean polymorphicVM;

    // --- Getters ---
    public String getPreset() { return preset; }
    public long getSeed() { return seed; }
    public List<String> getVirtualize() { return virtualize; }
    public List<String> getExclude() { return exclude; }
    public boolean isStringEncryption() { return stringEncryption; }
    public boolean isOpcodeShuffle() { return opcodeShuffle; }
    public boolean isIntegrityCheck() { return integrityCheck; }
    public boolean isPolymorphicVM() { return polymorphicVM; }

    // --- Setters (for Gson deserialization) ---
    public void setPreset(String preset) { this.preset = preset; }
    public void setSeed(long seed) { this.seed = seed; }
    public void setVirtualize(List<String> v) { this.virtualize = v; }
    public void setExclude(List<String> e) { this.exclude = e; }
    public void setStringEncryption(boolean b) { this.stringEncryption = b; }
    public void setOpcodeShuffle(boolean b) { this.opcodeShuffle = b; }
    public void setIntegrityCheck(boolean b) { this.integrityCheck = b; }
    public void setPolymorphicVM(boolean b) { this.polymorphicVM = b; }

    /**
     * Apply a preset — sets defaults, then overrides with explicit settings.
     */
    public void applyPreset(ProtectionPreset p) {
        switch (p) {
            case LIGHT:
                stringEncryption = false;
                opcodeShuffle = false;
                integrityCheck = false;
                polymorphicVM = false;
                break;
            case BALANCED:
                stringEncryption = true;
                opcodeShuffle = false;
                integrityCheck = false;
                polymorphicVM = false;
                break;
            case AGGRESSIVE:
                stringEncryption = true;
                opcodeShuffle = true;
                integrityCheck = true;
                polymorphicVM = true;
                break;
        }
    }

    /**
     * Check whether a class/method name matches a glob pattern.
     * Supports * wildcards. e.g., "com.example.*" matches "com.example.Foo".
     */
    public boolean matchesVirtualize(String className) {
        return matchesAny(className, virtualize);
    }

    public boolean matchesExclude(String className) {
        return matchesAny(className, exclude);
    }

    /** Check if a class name matches any glob pattern in the list. */
    public static boolean matchesAny(String className, List<String> patterns) {
        if (patterns == null || patterns.isEmpty()) return false;
        String dotted = className.replace('/', '.');
        for (String pattern : patterns) {
            if (globMatch(dotted, pattern)) return true;
        }
        return false;
    }

    /** Simple glob match: supports * at end. e.g., "com.foo.*" matches "com.foo.Bar". */
    private static boolean globMatch(String name, String pattern) {
        if (pattern.endsWith(".*")) {
            String prefix = pattern.substring(0, pattern.length() - 2);
            return name.equals(prefix) || name.startsWith(prefix + ".");
        }
        return name.equals(pattern);
    }

    // --- Factory ---

    public static VirtualizerConfig defaults() { return new VirtualizerConfig(); }
}
