package com.rivetz.bridge;

/**
 * Packages an instruction to be delivered to the Rivet
 */
public class Instruction {
    private int version = 1;
    private int mInstructionCode;
    protected byte[] mInstructionRecord;    // serialized instruction to send
    protected byte[] paramData;            // param data to wrap in instruction
    private Rivet mRivet;

    /**
     * Generate a new Instruction with the given instruction code. Use addParam to
     * extend the instruction with parameter data.
     * @param rivet pointer to the Rivet instance for sending this instruction
     * @param instructionCode see Rivet.INSTRUCT_... for defined instruction codes
     */
    public Instruction(Rivet rivet, int instructionCode) {
        mRivet = rivet;
        mInstructionCode = instructionCode;
        paramData = new byte[0];
    }

    /**
     * Parse the given byte array into an instruction object.
     * @param rivet pointer to the Rivet instance for sending this instruction
     * @param instructionBytes serialized instruction record to parse into the class
     */
    public Instruction(Rivet rivet, byte[] instructionBytes) {
        mRivet = rivet;
        mInstructionRecord = instructionBytes;
    }

    /**
     * Prepare the instruction as a byte array that can delivered to the mRivet.execute method
     */
    public void prepareData() {
        // start with version code
        mInstructionRecord = Utilities.int2bytes(Utilities.uint16_t,version);
        // add SPID
        mInstructionRecord = Utilities.bytesconcat(mInstructionRecord,Utilities.hexToBytes(mRivet.spid));
        // add instruction code
        mInstructionRecord = Utilities.bytesconcat(mInstructionRecord,Utilities.int2bytes(Utilities.uint16_t, mInstructionCode));
        // add parameter data
        mInstructionRecord = Utilities.bytesconcat(mInstructionRecord,Utilities.int2bytes(Utilities.uint16_t,paramData.length));
        mInstructionRecord = Utilities.bytesconcat(mInstructionRecord,paramData);
        // add empty signature
        mInstructionRecord = Utilities.bytesconcat(mInstructionRecord,Utilities.int2bytes(Utilities.uint16_t, 0));

    }

    /**
     * Sends the instruction to the mRivet.
     *
     * Instructions are built up by instantiating and instance with an instruction
     * type and then adding parameter data, or by providing a fully prepared instruction
     * record to the constructor.
     * @return mRivet response data containing the original bytes and the parsed elements
     */
    public RivetResponse send() {
        if (mInstructionRecord == null) {
            prepareData();
        }
        try {
            byte[] responseRecord = mRivet.binder.api.execute(mRivet.spid, mInstructionRecord);
            if (responseRecord == null || responseRecord.length == 0) {
                return new RivetResponse(mRivet.binder.api.getStatus());
            } else {
                return new RivetResponse(responseRecord);
            }
        } catch(Exception e) {
            return new RivetResponse(Rivet.ERROR_UNKNOWN);
        }
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
    public void addParam(String extraId, Object value) {
        if (extraId == Rivet.EXTRA_USAGERULES) {
            Rivet.UsageRule[] rules = (Rivet.UsageRule[])value;
            paramData = Utilities.bytesconcat(paramData,Utilities.int2bytes(Utilities.uint16_t, rules.length));
            for (Rivet.UsageRule rule : rules) {
                paramData = Utilities.bytesconcat(paramData,Utilities.int2bytes(Utilities.uint16_t,rule.getValue()));
            }
        } else if (extraId.matches("^("+Rivet.EXTRATYPE_STRING+"_).*")) {
            paramData = Utilities.bytesconcat(paramData,Utilities.stringToByteStruct((String) value));
        } else if (extraId.matches("^("+Rivet.EXTRATYPE_UINT8+"_).*")) {
            paramData = Utilities.bytesconcat(paramData,Utilities.int2bytes(Utilities.uint8_t,(Integer)value));
        } else if (extraId.matches("^("+Rivet.EXTRATYPE_UINT16+"_).*")) {
            paramData = Utilities.bytesconcat(paramData,Utilities.int2bytes(Utilities.uint16_t,(Integer)value));
        } else if (extraId.matches("^("+Rivet.EXTRATYPE_UINT32+"_).*")) {
            paramData = Utilities.bytesconcat(paramData,Utilities.int2bytes(Utilities.uint32_t,(Integer)value));
        } else if (extraId.matches("^("+Rivet.EXTRATYPE_UINT64+"_).*")) {
            paramData = Utilities.bytesconcat(paramData,Utilities.int2bytes(Utilities.uint64_t,(Integer)value));
        } else if (extraId.matches("^("+Rivet.EXTRATYPE_BOOLEAN+"_).*")) {
            paramData = Utilities.bytesconcat(paramData,Utilities.int2bytes(Utilities.uint8_t, (Boolean) value ? 1 : 0));
        } else if (extraId.matches("^("+Rivet.EXTRATYPE_HEXSTRING +"_).*")) {
            byte[] valueNew = Utilities.hexToBytes((String) value);
            byte[] lengthBytes = Utilities.int2bytes(Utilities.uint16_t, valueNew.length);
            paramData = Utilities.bytesconcat(paramData, Utilities.bytesconcat(lengthBytes, valueNew));
            paramData = Utilities.bytesconcat(paramData, valueNew);
        } else if (extraId.matches("^("+Rivet.EXTRATYPE_BYTES +"_).*")) {
            byte[] valueNew = (byte[])value;
            byte[] lengthBytes = Utilities.int2bytes(Utilities.uint16_t, valueNew.length);
            paramData = Utilities.bytesconcat(paramData, Utilities.bytesconcat(lengthBytes, valueNew));
            paramData = Utilities.bytesconcat(paramData, valueNew);
        } else {
            // TODO: this indicates an error that should not be syntactically available
        }
    }
}
