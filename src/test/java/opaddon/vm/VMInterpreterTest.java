package opaddon.vm;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the VMInterpreter using hand-written ISA programs.
 */
class VMInterpreterTest {

    @Test
    void intAdd() {
        TestPrograms.Program p = TestPrograms.intAdd();
        Object result = VMInterpreter.execute(p.code(), p.constants(), new Object[]{3, 5});
        assertEquals(8, result);
    }

    @Test
    void intAddNegative() {
        TestPrograms.Program p = TestPrograms.intAdd();
        Object result = VMInterpreter.execute(p.code(), p.constants(), new Object[]{-3, -5});
        assertEquals(-8, result);
    }

    @Test
    void intMultiply() {
        TestPrograms.Program p = TestPrograms.intMultiply();
        Object result = VMInterpreter.execute(p.code(), p.constants(), new Object[]{6, 7});
        assertEquals(42, result);
    }

    @Test
    void intComplex() {
        TestPrograms.Program p = TestPrograms.intComplex();
        Object result = VMInterpreter.execute(p.code(), p.constants(), new Object[]{2, 3, 4});
        assertEquals(10, result); // 2*3 + 4
    }

    @Test
    void intNegate() {
        TestPrograms.Program p = TestPrograms.intNegate();
        assertEquals(5, VMInterpreter.execute(p.code(), p.constants(), new Object[]{-5}));
        assertEquals(-10, VMInterpreter.execute(p.code(), p.constants(), new Object[]{10}));
        assertEquals(0, VMInterpreter.execute(p.code(), p.constants(), new Object[]{0}));
    }

    @Test
    void intDivide() {
        TestPrograms.Program p = TestPrograms.intDivide();
        assertEquals(5, VMInterpreter.execute(p.code(), p.constants(), new Object[]{10, 2}));
        assertEquals(3, VMInterpreter.execute(p.code(), p.constants(), new Object[]{7, 2})); // integer division
    }

    @Test
    void intRemainder() {
        TestPrograms.Program p = TestPrograms.intRemainder();
        assertEquals(1, VMInterpreter.execute(p.code(), p.constants(), new Object[]{10, 3}));
        assertEquals(0, VMInterpreter.execute(p.code(), p.constants(), new Object[]{8, 4}));
    }

    @Test
    void longAdd() {
        TestPrograms.Program p = TestPrograms.longAdd();
        Object result = VMInterpreter.execute(p.code(), p.constants(), new Object[]{100L, 200L});
        assertEquals(300L, result);
    }

    @Test
    void floatAdd() {
        TestPrograms.Program p = TestPrograms.floatAdd();
        Object result = VMInterpreter.execute(p.code(), p.constants(), new Object[]{2.5f, 3.5f});
        assertEquals(6.0f, (Float) result, 0.0001f);
    }

    @Test
    void doubleAdd() {
        TestPrograms.Program p = TestPrograms.doubleAdd();
        Object result = VMInterpreter.execute(p.code(), p.constants(), new Object[]{2.5, 3.5});
        assertEquals(6.0, (Double) result, 0.0001);
    }

    @Test
    void intMax() {
        TestPrograms.Program p = TestPrograms.intMax();
        assertEquals(5, VMInterpreter.execute(p.code(), p.constants(), new Object[]{3, 5}));
        assertEquals(7, VMInterpreter.execute(p.code(), p.constants(), new Object[]{7, 2}));
        assertEquals(0, VMInterpreter.execute(p.code(), p.constants(), new Object[]{0, 0}));
    }

    @Test
    void intAbs() {
        TestPrograms.Program p = TestPrograms.intAbs();
        assertEquals(5, VMInterpreter.execute(p.code(), p.constants(), new Object[]{-5}));
        assertEquals(10, VMInterpreter.execute(p.code(), p.constants(), new Object[]{10}));
        assertEquals(0, VMInterpreter.execute(p.code(), p.constants(), new Object[]{0}));
    }

    @Test
    void sumToN() {
        TestPrograms.Program p = TestPrograms.sumToN();
        assertEquals(15, VMInterpreter.execute(p.code(), p.constants(), new Object[]{5}));   // 1+2+3+4+5
        assertEquals(55, VMInterpreter.execute(p.code(), p.constants(), new Object[]{10}));  // 1+...+10
        assertEquals(0, VMInterpreter.execute(p.code(), p.constants(), new Object[]{0}));    // empty
        assertEquals(1, VMInterpreter.execute(p.code(), p.constants(), new Object[]{1}));    // just 1
    }

    @Test
    void factorial() {
        TestPrograms.Program p = TestPrograms.factorial();
        assertEquals(120, VMInterpreter.execute(p.code(), p.constants(), new Object[]{5}));   // 5!
        assertEquals(1, VMInterpreter.execute(p.code(), p.constants(), new Object[]{0}));     // 0! = 1
        assertEquals(1, VMInterpreter.execute(p.code(), p.constants(), new Object[]{1}));     // 1!
        assertEquals(3628800, VMInterpreter.execute(p.code(), p.constants(), new Object[]{10})); // 10!
    }

    @Test
    void constantReturn() {
        TestPrograms.Program p = TestPrograms.constantReturn();
        assertEquals(42, VMInterpreter.execute(p.code(), p.constants(), new Object[]{}));
    }

    @Test
    void voidNoop() {
        TestPrograms.Program p = TestPrograms.voidNoop();
        assertNull(VMInterpreter.execute(p.code(), p.constants(), new Object[]{}));
    }

    @Test
    void stringLdc() {
        TestPrograms.Program p = TestPrograms.stringLdc();
        assertEquals("hello", VMInterpreter.execute(p.code(), p.constants(), new Object[]{}));
    }

    @Test
    void constantLdc() {
        TestPrograms.Program p = TestPrograms.constantLdc();
        assertEquals(12345, VMInterpreter.execute(p.code(), p.constants(), new Object[]{}));
    }

    @Test
    void multipleInvocationsYieldSameResults() {
        // Verify the interpreter produces consistent results across multiple calls
        TestPrograms.Program add = TestPrograms.intAdd();
        for (int i = 0; i < 100; i++) {
            assertEquals(i + (i * 2), VMInterpreter.execute(add.code(), add.constants(),
                new Object[]{i, i * 2}));
        }
    }
}
