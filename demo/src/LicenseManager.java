import opaddon.annotation.Virtualize;

/**
 * LicenseManager — a realistic protected application.
 *
 * Contains proprietary algorithms that must NOT be visible to decompilers:
 *   - License key validation with embedded secret checksums
 *   - Feature flags derived from license hash
 *   - Subscription expiry computation
 *   - API token generation
 *
 * BUILD & VERIFY:
 *   cd demo && bash build-and-verify.sh
 */
public class LicenseManager {

    // ── Embedded secrets — must be hidden from decompilers ──────────
    private static final String[]  VALID_PREFIXES = {"XK", "LM", "ZQ", "VR"};
    private static final int[]     MAGIC_SEEDS    = {0x5F37, 0x9E37, 0x2B99, 0x7D1F};
    private static final long      MASTER_HASH    = 0x6C8A2E4F9B0D1357L;

    public static void main(String[] args) {
        LicenseManager lm = new LicenseManager();
        String key = args.length > 0 ? args[0] : "XK7m-9pQ2-vR4n-W8sT";

        System.out.println("License valid:   " + lm.validateLicense(key));
        System.out.println("Features:        " + lm.getFeatureFlags(key));
        System.out.println("Expires in days: " + lm.computeExpiry(key));
        System.out.println("API token:       " + lm.generateToken(key, 0));
        System.out.println("Risk tier:       " + lm.computeRiskTier(7, 3, 25000));
        System.out.println("Build hash:      " + lm.getBuildFingerprint());
    }

    // ════════════════════════════════════════════════════════════════
    //  PROTECTED METHODS — algorithms hidden from decompilers
    // ════════════════════════════════════════════════════════════════

    /**
     * Multi-stage license validation with embedded checksums.
     * A decompiler should NOT see this algorithm.
     */
    @Virtualize
    public boolean validateLicense(String key) {
        if (key == null || key.length() < 8) return false;

        // Stage 1: Prefix validation
        boolean validPrefix = false;
        for (String prefix : VALID_PREFIXES) {
            if (key.startsWith(prefix)) { validPrefix = true; break; }
        }
        if (!validPrefix) return false;

        // Stage 2: Checksum over first 8 chars
        int cksum = 0;
        for (int i = 0; i < Math.min(8, key.length()); i++) {
            cksum = (cksum * 31 + key.charAt(i)) & 0xFF;
        }
        if (cksum != 0x7F) return false;

        // Stage 3: Segment count
        String[] parts = key.split("-");
        if (parts.length != 4) return false;
        for (String p : parts) {
            if (p.length() != 4 && p.length() != 5) return false;
        }

        // Stage 4: Final hash check
        long hash = 0;
        for (int i = 0; i < key.length(); i++) {
            hash = hash * 0x5BD1E995 + key.charAt(i);
            hash = Long.rotateLeft(hash, 13);
            hash *= 0xC96C5795;
        }
        return hash == MASTER_HASH;
    }

    /**
     * Feature bitmask derived from license hash — proprietary encoding.
     */
    @Virtualize
    public int getFeatureFlags(String key) {
        if (key == null) return 0;
        int flags = 0;
        int hash = 0x811C9DC5;
        for (int i = 0; i < key.length(); i++) {
            hash ^= key.charAt(i);
            hash *= 0x01000193;
        }
        // Extract feature bits from hash nibbles
        for (int i = 0; i < 16; i++) {
            int nibble = (hash >> (i * 2)) & 0x3;
            if (nibble >= 2) flags |= (1 << i);
        }
        return flags & 0xFFFF;
    }

    /**
     * Subscription expiry — reverse-engineerable without protection.
     */
    @Virtualize
    public int computeExpiry(String key) {
        if (key == null) return 0;
        long hash = 0;
        for (int i = 0; i < key.length(); i++) {
            hash = hash * 0x9E3779B9 + key.charAt(i);
        }

        // Extract expiry from hash bits
        int days = (int) ((hash & 0x7FFFFFFF) % 365);
        // Premium keys get +180 days
        if (key.startsWith("ZQ") || key.contains("-9pQ")) {
            days += 180;
        }
        // Clamp
        if (days > 365) days = 365;
        if (days < 7)  days = 7;
        return days;
    }

    /**
     * API token generator — cryptographic algorithm.
     */
    @Virtualize
    public String generateToken(String seed, int index) {
        if (seed == null) return "";
        long h1 = 0x5F3759DF ^ index;
        long h2 = 0x9E3779B9;
        for (int i = 0; i < seed.length(); i++) {
            h1 = Long.rotateLeft(h1 ^ seed.charAt(i), 7) + h2;
            h2 = Long.rotateRight(h2, 3) ^ h1;
        }
        h1 ^= h2;
        // Format as hex token
        return String.format("%04x-%04x-%04x",
            (int)(h1 & 0xFFFF),
            (int)((h1 >> 16) & 0xFFFF),
            (int)(h2 & 0xFFFF));
    }

    /**
     * Risk scoring algorithm — core business logic.
     */
    @Virtualize
    public int computeRiskTier(int baseScore, int severity, int txAmount) {
        int score = baseScore;
        if (severity > 0) {
            long factor = (long) severity * severity;
            score = (int)(score + factor / 10);
        }
        if (txAmount > 0) {
            int log = 0, t = txAmount;
            while (t > 1) { t >>= 1; log++; }
            score += log * 5;
        }
        // Map to tier
        if (score >= 200) return 4;  // Critical
        if (score >= 100) return 3;  // High
        if (score >= 50)  return 2;  // Medium
        if (score >= 20)  return 1;  // Low
        return 0;                    // None
    }

    // ════════════════════════════════════════════════════════════════
    //  Non-protected utilities
    // ════════════════════════════════════════════════════════════════

    public String getBuildFingerprint() {
        return "LM-v4.2-" + Long.toHexString(MASTER_HASH).substring(0, 8);
    }
}
