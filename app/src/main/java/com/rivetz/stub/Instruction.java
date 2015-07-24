package com.rivetz.stub;

import java.util.ArrayList;

/**
 * Packages an instruction to be delivered to the Rivet
 */
public class Instruction {
    private int version = 1;
    private int instructionCode;
    protected byte[] instructionRecord;    // serialized instruction to send
    protected byte[] paramData;            // param data to wrap in instruction
    private Rivet rivet;

    public Instruction(Rivet rivetGiven, int codeGiven) {
        rivet = rivetGiven;
        instructionCode = codeGiven;
        paramData = new byte[0];
    }

    public Instruction(Rivet rivetGiven, byte[] instructionRecordGiven) {
        rivet = rivetGiven;
        instructionRecord = instructionRecordGiven;
    }

    public void prepareData() {
        // start with version code
        instructionRecord = Utilities.int2bytes(Utilities.uint16_t,version);
        // add SPID
        instructionRecord = Utilities.bytesconcat(instructionRecord,Utilities.hexToBytes(rivet.spid));
        // add instruction code
        instructionRecord = Utilities.bytesconcat(instructionRecord,Utilities.int2bytes(Utilities.uint16_t, instructionCode));
        // add parameter data
        instructionRecord = Utilities.bytesconcat(instructionRecord,Utilities.int2bytes(Utilities.uint16_t,paramData.length));
        instructionRecord = Utilities.bytesconcat(instructionRecord,paramData);
        // add empty signature
        instructionRecord = Utilities.bytesconcat(instructionRecord,Utilities.int2bytes(Utilities.uint16_t, 0));

    }

    /**
     * Sends the instruction to the rivet.
     *
     * Instructions are built up by instantiating and instance with an instruction
     * type and then adding parameter data, or by providing a fully prepared instruction
     * record to the constructor.
     * @return rivet response data containing the original bytes and the parsed elements
     */
    public RivetResponse send() {
        if (instructionRecord == null) {
            prepareData();
        }
        try {
            byte[] responseRecord = rivet.binder.api.execute(rivet.spid, instructionRecord);
            if (responseRecord == null || responseRecord.length == 0) {
                return new RivetResponse(rivet.binder.api.getStatus());
            } else {
                return new RivetResponse(responseRecord);
            }
        } catch(Exception e) {
            return new RivetResponse(Rivet.ERROR_UNKNOWN);
        }
    }

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
