// IRivetzAPI.aidl
package com.rivetz.adapter;

// Declare any non-default types here with import statements

interface IRivetzAPI {
    int getStatus();
    String createKey(String spid, int keyType, String keyName, in int[] keyRules);
//    int deleteKey(String spid, String keyName);
//    int sign(String spid, String keyName, String payload);
//    int verify(String spid, String keyName, String signature, String payload);
//    int keyEnum(String spid);
}
