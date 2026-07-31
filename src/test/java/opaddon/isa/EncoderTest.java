package opaddon.isa;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class EncoderTest {

    @Test
    void roundTripSingleInstruction() {
        List<Instruction> original = List.of(
            Instruction.iconst(42)
        );
        byte[] encoded = Encoder.encode(original);
        List<Instruction> decoded = Encoder.decode(encoded);
        assertEquals(original, decoded);
    }

    @Test
    void roundTripMultipleInstructions() {
        List<Instruction> original = List.of(
            Instruction.iconst(10),
            Instruction.iconst(20),
            Instruction.iadd(),
            Instruction.ireturn()
        );
        byte[] encoded = Encoder.encode(original);
        List<Instruction> decoded = Encoder.decode(encoded);
        assertEquals(original, decoded);
    }

    @Test
    void roundTripAllArithmetic() {
        List<Instruction> original = Arrays.asList(
            Instruction.iconst(7),
            Instruction.iload(0),
            Instruction.iadd(),
            Instruction.isub(),
            Instruction.imul(),
            Instruction.idiv(),
            Instruction.irem(),
            Instruction.ineg(),
            Instruction.ireturn()
        );
        byte[] encoded = Encoder.encode(original);
        List<Instruction> decoded = Encoder.decode(encoded);
        assertEquals(original, decoded);
    }

    @Test
    void roundTripBranches() {
        List<Instruction> original = List.of(
            Instruction.iconst(1),
            Instruction.iconst(2),
            Instruction.if_icmpeq(10),
            Instruction.goto_(20),
            Instruction.ireturn()
        );
        byte[] encoded = Encoder.encode(original);
        List<Instruction> decoded = Encoder.decode(encoded);
        assertEquals(original, decoded);
    }

    @Test
    void roundTripLongConstant() {
        List<Instruction> original = List.of(
            Instruction.lconst(0x123456789ABCDEFL),
            Instruction.lreturn()
        );
        byte[] encoded = Encoder.encode(original);
        List<Instruction> decoded = Encoder.decode(encoded);
        assertEquals(original, decoded);
    }

    @Test
    void roundTripNegativeValues() {
        List<Instruction> original = List.of(
            Instruction.iconst(-1),
            Instruction.iconst(Integer.MIN_VALUE),
            Instruction.iconst(Integer.MAX_VALUE),
            Instruction.ireturn()
        );
        byte[] encoded = Encoder.encode(original);
        List<Instruction> decoded = Encoder.decode(encoded);
        assertEquals(original, decoded);
    }

    @Test
    void roundTripSwitches() {
        List<Instruction> original = List.of(
            Instruction.iload(0),
            Instruction.iload(1),
            Instruction.swap(),
            Instruction.isub(),
            Instruction.ireturn()
        );
        byte[] encoded = Encoder.encode(original);
        List<Instruction> decoded = Encoder.decode(encoded);
        assertEquals(original, decoded);
    }

    @Test
    void emptyProgram() {
        List<Instruction> original = List.of();
        byte[] encoded = Encoder.encode(original);
        assertEquals(0, encoded.length);
        List<Instruction> decoded = Encoder.decode(encoded);
        assertTrue(decoded.isEmpty());
    }

    @Test
    void encodedSizePositive() {
        List<Instruction> insns = List.of(Instruction.iconst(42));
        assertTrue(Encoder.encodedSize(insns) > 0);
    }

    @Test
    void unknownOpcodeThrows() {
        byte[] bad = {(byte) 0xFF};
        assertThrows(IllegalArgumentException.class, () -> Encoder.decode(bad));
    }
}
