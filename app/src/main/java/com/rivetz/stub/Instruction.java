package com.rivetz.stub;

import java.util.ArrayList;

/**
 * Packages and instruction to be delivered to the Rivet
 */
public class Instruction {
    private int version = 1;
    private int instructionCode;
    protected byte[] instructionRecord;    // serialized instruction to send
    protected byte[] paramData;            // param data to wrap in instruction
    protected ResultData resultData;
    private Rivet rivet;

    public Instruction(Rivet rivetGiven, int codeGiven) {
        rivet = rivetGiven;
        resultData = new ResultData();
        instructionCode = codeGiven;
        paramData = new byte[0];
    }

    public Instruction(Rivet rivetGiven, byte[] instructionRecordGiven) {
        rivet = rivetGiven;
        resultData = new ResultData();
        instructionRecord = instructionRecordGiven;
    }

    public void prepareData() {
        // start with version code
        instructionRecord = Utilities.int2bytes(Constants.uint16_t,version);
        // add SPID
        instructionRecord = Utilities.bytesconcat(instructionRecord,Utilities.hexToBytes(rivet.spid));
        // add instruction code
        instructionRecord = Utilities.bytesconcat(instructionRecord,Utilities.int2bytes(Constants.uint16_t, instructionCode));
        // add parameter data
        instructionRecord = Utilities.bytesconcat(instructionRecord,Utilities.int2bytes(Constants.uint16_t,paramData.length));
        instructionRecord = Utilities.bytesconcat(instructionRecord,paramData);
    }

    public void parseResponse() {
        if (resultData.record == null) {
            resultData.status = Rivet.ERROR_UNKNOWN;
        }
        int offset = 0;

        // get version
        int versionReturned = Utilities.extractInt(resultData.record, offset, Constants.uint16_t);
        offset += Constants.uint16_t;
        // get spid
        String spidReturned = Utilities.bytes2string(Utilities.bytesofbytes(
                resultData.record, offset, ServiceProviderRecord.SPID_DATA_VALUE_SIZE));
        offset += ServiceProviderRecord.SPID_DATA_VALUE_SIZE;
        // get instruction code
        int instructionCodeReturned = Utilities.extractInt(resultData.record, offset, Constants.uint16_t);
        offset += Constants.uint16_t;
        // get data
        int dataLength = Utilities.extractInt(resultData.record, offset, Constants.uint16_t);
        offset += Constants.uint16_t;
        resultData.payload = Utilities.bytesofbytes(resultData.record, offset, dataLength);
        offset += dataLength;
        // get signature
        int sigLength = Utilities.extractInt(resultData.record, offset, Constants.uint16_t);
        offset += Constants.uint16_t;
        resultData.signature = Utilities.bytesofbytes(resultData.record, offset, sigLength);
        offset += sigLength;
        // get SPR
        int sprVersion = Utilities.extractInt(resultData.record, offset, Constants.uint16_t);
        offset += Constants.uint16_t;
        int sprLength = Utilities.extractInt(resultData.record, offset, Constants.uint32_t);
        offset += Constants.uint32_t;
        byte[] sprBytes = Utilities.bytesofbytes(resultData.record, offset, sprLength);

        if (versionReturned != version || instructionCodeReturned != instructionCode) {
            resultData.status = Rivet.ERROR_VERSION_ERROR;
            resultData.record = null;
        } else {
            // save SPR as it may have been changed
            resultData.spRecord = new ServiceProviderRecord(sprBytes);
        }
    }


    public ResultData send() {
        if (instructionRecord == null) {
            prepareData();
        }
        try {
            resultData.record = rivet.binder.api.execute(rivet.spid, instructionRecord);
            if (resultData.record == null || resultData.record.length == 0) {
                resultData.status = rivet.binder.api.getStatus();
            } else {
                parseResponse();
            }
        } catch(Exception e) {
            resultData.status = Rivet.ERROR_UNKNOWN;
        }
        return resultData;
    }

    public void addParam(String extraId, Object value) {
        if (extraId == Rivet.EXTRA_USAGERULES) {
            Rivet.UsageRule[] rules = (Rivet.UsageRule[])value;
            Utilities.bytesconcat(paramData,Utilities.int2bytes(Utilities.uint16_t, rules.length));
            for (Rivet.UsageRule rule : rules) {
                Utilities.bytesconcat(paramData,Utilities.int2bytes(Utilities.uint16_t,rule.getValue()));
            }
        } else if (extraId.matches("^("+Rivet.EXTRATYPE_STRING+"_).*")) {
            Utilities.bytesconcat(paramData,Utilities.stringToByteStruct((String) value));
        } else if (extraId.matches("^("+Rivet.EXTRATYPE_UINT8+"_).*")) {
            Utilities.bytesconcat(paramData,Utilities.int2bytes(Constants.uint8_t,(Integer)value));
        } else if (extraId.matches("^("+Rivet.EXTRATYPE_UINT16+"_).*")) {
            Utilities.bytesconcat(paramData,Utilities.int2bytes(Constants.uint16_t,(Integer)value));
        } else if (extraId.matches("^("+Rivet.EXTRATYPE_UINT32+"_).*")) {
            Utilities.bytesconcat(paramData,Utilities.int2bytes(Constants.uint32_t,(Integer)value));
        } else if (extraId.matches("^("+Rivet.EXTRATYPE_UINT64+"_).*")) {
            Utilities.bytesconcat(paramData,Utilities.int2bytes(Constants.uint64_t,(Integer)value));
        } else if (extraId.matches("^("+Rivet.EXTRATYPE_BOOLEAN+"_).*")) {
            Utilities.bytesconcat(paramData,Utilities.int2bytes(Constants.uint8_t, (Boolean) value ? 1 : 0));
        } else if (extraId.matches("^("+Rivet.EXTRATYPE_HEXSTRING +"_).*")) {
            byte[] valueNew = Utilities.hexToBytes((String) value);
            byte[] lengthBytes = Utilities.int2bytes(Constants.uint16_t, valueNew.length);
            Utilities.bytesconcat(paramData, Utilities.bytesconcat(lengthBytes, valueNew));
            Utilities.bytesconcat(paramData, valueNew);
        } else if (extraId.matches("^("+Rivet.EXTRATYPE_BYTES +"_).*")) {
            byte[] valueNew = (byte[])value;
            byte[] lengthBytes = Utilities.int2bytes(Constants.uint16_t, valueNew.length);
            Utilities.bytesconcat(paramData, Utilities.bytesconcat(lengthBytes, valueNew));
            Utilities.bytesconcat(paramData, valueNew);
        } else {
            resultData.status = Rivet.ERROR_UNKNOWN_TYPE;
        }
    }
}
