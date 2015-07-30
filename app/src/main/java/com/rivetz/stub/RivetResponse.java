package com.rivetz.stub;

/**
 * Parses the response from a RivetInstruction.
 *
 * The original record is available as an attribute, but the data is parsed for the
 * payload, result status, signature, response data (payload) and Service Provider Record.
 * The SPID and instruction code that accompanied the instruction record are also
 * available in the response. They should match,
 */
public class RivetResponse {
    public byte[] record;
    public byte[] payload;
    public byte[] signature;
    public String spid;
    public int instructionCode;
    public ServiceProviderRecord spRecord;
    int status = Rivet.ERROR_UNKNOWN;

    /**
     * Creates a response record with the given status code
     * @param statusGiven This should be one of the constants defined in Rivet.ERROR_...
     */
    public RivetResponse(int statusGiven) {
        status = statusGiven;
    }

    /**
     * Constructs a response record from the the given byte stream
     * @param recordGiven contains a serialized response record to be parsed into the class
     */
    public RivetResponse(byte[] recordGiven) {
        record = recordGiven;
        int offset = 0;

        // get version
        int versionReturned = Utilities.extractInt(record, offset, Utilities.uint16_t);
        offset += Utilities.uint16_t;
        // get spid
        spid = Utilities.bytes2string(Utilities.bytesofbytes(
                record, offset, ServiceProviderRecord.SPID_DATA_VALUE_SIZE));
        offset += ServiceProviderRecord.SPID_DATA_VALUE_SIZE;
        // get instruction code
        instructionCode = Utilities.extractInt(record, offset, Utilities.uint16_t);
        offset += Utilities.uint16_t;
        // get status code
        int returnStatus = Utilities.extractInt(record, offset, Utilities.uint32_t);
        offset += Utilities.uint32_t;
        // get data
        int dataLength = Utilities.extractInt(record, offset, Utilities.uint16_t);
        offset += Utilities.uint16_t;
        payload = Utilities.bytesofbytes(record, offset, dataLength);
        offset += dataLength;
        // get signature
        int sigLength = Utilities.extractInt(record, offset, Utilities.uint16_t);
        offset += Utilities.uint16_t;
        signature = Utilities.bytesofbytes(record, offset, sigLength);
        offset += sigLength;
        // get SPR
        int sprLength = Utilities.extractInt(record, offset, Utilities.uint32_t);
        // extract SPR including initial length value
        byte[] sprBytes = Utilities.bytesofbytes(record, offset, sprLength+Utilities.uint32_t);

        if (returnStatus == Rivet.ERROR_NONE) {
            spRecord = new ServiceProviderRecord(sprBytes);
        }
    }

}
