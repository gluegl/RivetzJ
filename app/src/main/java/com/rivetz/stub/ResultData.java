package com.rivetz.stub;

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
