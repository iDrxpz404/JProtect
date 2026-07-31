package opaddon.hardening;

import opaddon.isa.Opcode;

import java.util.*;

/**
 * Per-build opcode byte shuffling.
 *
 * Generates a randomized mapping from Opcode → shuffled byte,
 * and the reverse mapping (shuffled byte → original opcode byte)
 * for the VM interpreter to use at runtime.
 */
public final class OpcodeShuffler {

    private OpcodeShuffler() {}

    /** Number of possible byte values */
    private static final int SLOTS = 256;

    /**
     * Generate forward mapping: original opcode byte → shuffled byte.
     * Returns byte[256] where result[originalByte &amp; 0xFF] = shuffledByte.
     * Unused slots map to themselves.
     */
    public static byte[] generateForwardMapping(long seed) {
        // Collect usable slots and assigned opcodes
        Opcode[] all = Opcode.values();
        byte[] forward = new byte[SLOTS];

        // Initialize: every slot maps to itself (identity for unused)
        for (int i = 0; i < SLOTS; i++) {
            forward[i] = (byte) i;
        }

        // Collect original bytes that need shuffling
        List<Byte> originalBytes = new ArrayList<>();
        for (Opcode op : all) {
            if (op == Opcode.NOP) continue; // keep NOP as 0x00
            originalBytes.add(op.code());
        }

        // Generate shuffled values from the same set
        List<Byte> shuffledValues = new ArrayList<>(originalBytes);
        Random rng = new Random(seed);
        Collections.shuffle(shuffledValues, rng);

        // Build forward mapping
        for (int i = 0; i < originalBytes.size(); i++) {
            byte orig = originalBytes.get(i);
            byte shuffled = shuffledValues.get(i);
            forward[orig & 0xFF] = shuffled;
        }

        return forward;
    }

    /**
     * Generate reverse mapping from forward mapping.
     * reverse[shuffledByte &amp; 0xFF] = originalOpcodeByte.
     */
    public static byte[] generateReverseMapping(byte[] forward) {
        byte[] reverse = new byte[SLOTS];
        for (int i = 0; i < SLOTS; i++) {
            reverse[i] = (byte) i; // identity default
        }
        for (int i = 0; i < SLOTS; i++) {
            byte shuffled = forward[i];
            reverse[shuffled & 0xFF] = (byte) i;
        }
        return reverse;
    }

    /**
     * Return the identity (no-shuffle) reverse mapping.
     * Used when seed is 0.
     */
    public static byte[] identityMapping() {
        byte[] map = new byte[SLOTS];
        for (int i = 0; i < SLOTS; i++) {
            map[i] = (byte) i;
        }
        return map;
    }
}
