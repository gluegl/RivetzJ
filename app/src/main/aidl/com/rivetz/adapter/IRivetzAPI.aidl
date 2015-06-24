// IRivetzAPI.aidl
package com.rivetz.adapter;

// Declare any non-default types here with import statements

interface IRivetzAPI {
    int getStatus();
    byte[] getServiceProviderRecord(String spid);
    byte[] execute(String spid, in byte[] instruction);
}
