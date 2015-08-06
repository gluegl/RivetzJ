package com.rivetz.bridge;

import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * Keys can be restrained by key usage rules that enforce the conditions under
 * which they are used. Key usage rules are attached to KeyRecords. Usage rule
 * types are define in Rivet.java
 */
public class KeyUsageRule {
    Rivet.UsageRule mRule;

    /**
     *
     * @param rule
     */
    public KeyUsageRule(Rivet.UsageRule rule) {
        mRule = rule;
    }
    public KeyUsageRule(String ruleStr) {
        mRule = Rivet.UsageRule.valueOf(ruleStr);
    }
    public KeyUsageRule(JSONObject json) {
        parseJson(json);
    }
    public KeyUsageRule(byte[] bytes) {
        if (!Deserialize(bytes)) {
            Log.e(Utilities.LOG_TAG, "byte[] Parse error of KeyUsageRule");
        }
    }

    public void parseJson(JSONObject json) {
        try {
            mRule = Rivet.UsageRule.valueOf(json.getString("mRule"));
        } catch(JSONException e) {
            Log.e(Utilities.LOG_TAG, "JSON Parse error of KeyUsageRule");
        }
    }
    public JSONObject getJson() {
        JSONObject json = new JSONObject();
        try {
            json.put("mRule", mRule.toString());
        } catch(JSONException e) {
            json = null;
        }
        return json;
    }

    @Override
    public String toString() {
        return(getJson().toString());
    }

    public byte[] Serialize() {
        try {
            // Build byte array values
            byte[] rule_type = Utilities.int2bytes(Utilities.uint16_t, mRule.getValue());

            return rule_type;

        } catch(Exception e ) {
            Log.e(Utilities.LOG_TAG, "byte write error of KeyUsageRule");
            return null;
        }
    }

    public boolean Deserialize(byte[] bytedata) {
        if (Utilities.uint16_t != bytedata.length) return false;
        int new_rule = Utilities.bytes2int(bytedata,Utilities.uint16_t);
        Log.d(Utilities.LOG_TAG, "ParseTest KeyUsageRule Type = " + String.valueOf(new_rule));
        if (new_rule <= 0 || new_rule > Rivet.UsageRule.values().length) return false;

        mRule = Rivet.UsageRule.values()[new_rule - 1];

        return true;
    }
}
