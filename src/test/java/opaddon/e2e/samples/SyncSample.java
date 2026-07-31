package opaddon.e2e.samples;

import opaddon.annotation.Virtualize;

/**
 * Test fixture with synchronized blocks.
 */
public class SyncSample {

    /** Synchronized instance method — uses MONITORENTER/EXIT on 'this' */
    @Virtualize
    public synchronized int syncAdd(int a, int b) {
        return a + b;
    }

    /** Explicit synchronized block */
    @Virtualize
    public int syncBlock(int x) {
        synchronized (this) {
            return x * 2;
        }
    }

    /** Synchronized block with local variable */
    @Virtualize
    public int syncCounter() {
        int count = 0;
        synchronized (this) {
            count = 42;
        }
        return count;
    }
}
