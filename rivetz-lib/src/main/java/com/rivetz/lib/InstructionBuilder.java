package com.rivetz.lib;

/**
 * Builds an InstructionRecord  for delivery to the Rivet
 */
public class InstructionBuilder {
    private int version = 1;
    private int mInstructionCode;
    protected byte[] mInstructionRecord;    // serialized instruction to send
    protected byte[] paramData;            // param data to wrap in instruction
    private String spid;

    /**
     * Generate a new Instruction with the given instruction code. Use addParam to
     * extend the instruction with parameter data.
     * @param rivet pointer to the Rivet instance for sending this instruction
     * @param instructionCode see Rivet.INSTRUCT_... for defined instruction codes
     */
    public InstructionBuilder(RivetBase rivet, int instructionCode) {
        spid = rivet.spid;
        mInstructionCode = instructionCode;
        paramData = new byte[0];
    }

    /**
     * Parse the given byte array into an instruction object.
     * @param rivet pointer to the Rivet instance for sending this instruction
     * @param instructionBytes serialized instruction record to parse into the class
     * @deprecated use {@link InstructionRecord#InstructionRecord(byte[])} instead
     */
    @Deprecated
    public InstructionBuilder(RivetBase rivet, byte[] instructionBytes) {
        spid = rivet.spid;
        mInstructionRecord = instructionBytes;
    }

    /**
     * Prepare the instruction as an InstructionRecord (which contains an immutable byte array)
     */
    public InstructionRecord prepareData() {
        // start with version code
        mInstructionRecord = Utilities.int2bytes(Utilities.uint16_t, version);
        // add SPID
        mInstructionRecord = Utilities.bytesconcat(mInstructionRecord,Utilities.hexToBytes(spid));
        // add instruction code
        mInstructionRecord = Utilities.bytesconcat(mInstructionRecord,Utilities.int2bytes(Utilities.uint16_t, mInstructionCode));
        // add parameter data
        mInstructionRecord = Utilities.bytesconcat(mInstructionRecord,Utilities.int2bytes(Utilities.uint16_t,paramData.length));
        mInstructionRecord = Utilities.bytesconcat(mInstructionRecord,paramData);
        // add empty signature
        mInstructionRecord = Utilities.bytesconcat(mInstructionRecord,Utilities.int2bytes(Utilities.uint16_t, 0));
        return new InstructionRecord(mInstructionRecord);
    }


    /**
     * Add a typed parameter to the instruction record.
     *
     * A parameter to an instruction is typed to one of the constants defined in
     * Rivet.EXTRA_... Each type has an inherent datatype which determines how it
     * is serialized into the instruction record.
     *
     * For example, if you call addParam with the extraId of Rivet.EXTRA_SPID this is
     * understood to be a string. The result
     * is that two bytes of length data plus the string chars are inserted into the
     * InstructionRecord
     * @param extraId refer to the constants defined in Rivet for extraId types
     * @param value the value of the parameter typed according to the extraId
     */
    public InstructionBuilder addParam(String extraId, Object value) {
        if (extraId.equals(RivetBase.EXTRA_USAGERULES)) {
            RivetBase.UsageRule[] rules = (RivetBase.UsageRule[])value;
            paramData = Utilities.bytesconcat(paramData,Utilities.int2bytes(Utilities.uint16_t, rules.length));
            for (RivetBase.UsageRule rule : rules) {
                paramData = Utilities.bytesconcat(paramData,Utilities.int2bytes(Utilities.uint16_t,rule.getValue()));
            }
        } else if (extraId.matches("^("+ RivetBase.EXTRATYPE_STRING+"_).*")) {
            paramData = Utilities.bytesconcat(paramData,Utilities.stringToByteStruct((String) value));
        } else if (extraId.matches("^("+ RivetBase.EXTRATYPE_UINT8+"_).*")) {
            paramData = Utilities.bytesconcat(paramData,Utilities.int2bytes(Utilities.uint8_t,(Integer)value));
        } else if (extraId.matches("^("+ RivetBase.EXTRATYPE_UINT16+"_).*")) {
            paramData = Utilities.bytesconcat(paramData,Utilities.int2bytes(Utilities.uint16_t,(Integer)value));
        } else if (extraId.matches("^("+ RivetBase.EXTRATYPE_UINT32+"_).*")) {
            paramData = Utilities.bytesconcat(paramData,Utilities.int2bytes(Utilities.uint32_t,(Integer)value));
        } else if (extraId.matches("^("+ RivetBase.EXTRATYPE_UINT64+"_).*")) {
            paramData = Utilities.bytesconcat(paramData,Utilities.int2bytes(Utilities.uint64_t,(Integer)value));
        } else if (extraId.matches("^("+ RivetBase.EXTRATYPE_BOOLEAN+"_).*")) {
            paramData = Utilities.bytesconcat(paramData,Utilities.int2bytes(Utilities.uint8_t, (Boolean) value ? 1 : 0));
        } else if (extraId.matches("^("+ RivetBase.EXTRATYPE_HEXSTRING +"_).*")) {
            byte[] valueNew = Utilities.hexToBytes((String) value);
            byte[] lengthBytes = Utilities.int2bytes(Utilities.uint16_t, valueNew.length);
            paramData = Utilities.bytesconcat(paramData, Utilities.bytesconcat(lengthBytes, valueNew));
            paramData = Utilities.bytesconcat(paramData, valueNew);
        } else if (extraId.matches("^("+ RivetBase.EXTRATYPE_BYTES +"_).*")) {
            byte[] valueNew = (byte[])value;
            byte[] lengthBytes = Utilities.int2bytes(Utilities.uint16_t, valueNew.length);
            paramData = Utilities.bytesconcat(paramData, Utilities.bytesconcat(lengthBytes, valueNew));
            paramData = Utilities.bytesconcat(paramData, valueNew);
        } else {
            // TODO: this indicates an error that should not be syntactically available
        }
        return this;
    }
}
