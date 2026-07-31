package opaddon.config;

import java.util.zip.CRC32;

/**
 * Integrity verification for PROGRAM byte arrays.
 * Computes a CRC32 checksum at build time, verifies at execution time.
 */
public final class IntegrityVerifier {

    private IntegrityVerifier() {}

    /**
     * Compute a CRC32 checksum for the given bytes.
     * Stored alongside the encrypted program in the constant table.
     */
    public static long computeChecksum(byte[] data) {
        CRC32 crc = new CRC32();
        crc.update(data);
        return crc.getValue();
    }

    /**
     * Compute checksum with a salt (seed-based).
     */
    public static long computeSaltedChecksum(byte[] data, long salt) {
        CRC32 crc = new CRC32();
        crc.update(data);
        // Mix in salt bytes
        for (int i = 0; i < 8; i++) {
            crc.update((int) (salt & 0xFF));
            salt >>>= 8;
        }
        return crc.getValue();
    }

    /**
     * Verify checksum at runtime. Throws SecurityException on mismatch.
     */
    public static void verify(byte[] data, long expectedChecksum, long salt) {
        long actual = computeSaltedChecksum(data, salt);
        if (actual != expectedChecksum) {
            throw new SecurityException(
                "PROGRAM integrity check failed: expected 0x" +
                Long.toHexString(expectedChecksum) + " but got 0x" +
                Long.toHexString(actual));
        }
    }
}
