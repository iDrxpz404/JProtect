package opaddon.config;

import java.util.zip.CRC32;

public final class IntegrityVerifier {

    private IntegrityVerifier() {}

    public static long computeChecksum(byte[] data) {
        CRC32 crc = new CRC32();
        crc.update(data);
        return crc.getValue();
    }

    public static long computeSaltedChecksum(byte[] data, long salt) {
        CRC32 crc = new CRC32();
        crc.update(data);
        for (int i = 0; i < 8; i++) {
            crc.update((int) (salt & 0xFF));
            salt >>>= 8;
        }
        return crc.getValue();
    }

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
