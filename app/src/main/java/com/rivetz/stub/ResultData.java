package com.rivetz.stub;

/**
 * A collection of entities available after executing and instruction.
 * Includes the signature and the complete and signed result record
 */
public class ResultData {
    byte[] record;                  // the entire result record
    byte[] payload;                 // the payload of the result response
    byte[] signature;               // the signature on the record
    int status = Rivet.ERROR_NONE;  // status code
    ServiceProviderRecord spRecord; // service provider record includes with response

    public String getHexSignature() {
        return Utilities.bytesToHex(signature);
    }
}
