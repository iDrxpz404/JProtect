package opaddon.config;

/**
 * Protection presets matching the spec: light, balanced, aggressive.
 */
public enum ProtectionPreset {
    /** Minimal protection: only virtualize @Virtualize methods, no hardening */
    LIGHT,
    /** Default: virtualize + XOR encryption + string encryption */
    BALANCED,
    /** Maximum: virtualize + encryption + polymorphic VM + integrity checks */
    AGGRESSIVE;

    public static ProtectionPreset fromString(String s) {
        if (s == null) return BALANCED;
        return switch (s.toLowerCase()) {
            case "light" -> LIGHT;
            case "aggressive" -> AGGRESSIVE;
            default -> BALANCED;
        };
    }
}
