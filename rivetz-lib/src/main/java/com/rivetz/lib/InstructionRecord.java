package com.rivetz.lib;

/**
 * InstructionRecord (Immutable)
 */
public class InstructionRecord {
    private final byte[] instructionBytes;

    /**
     * Don't use this, use InstructionBuilder to create
     * @param instructionBytes
     */
    public InstructionRecord(final byte[] instructionBytes) {
        this.instructionBytes = instructionBytes;
    }

    public byte[] getBytes() {
        return instructionBytes;
    }
}
