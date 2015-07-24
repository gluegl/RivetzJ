package com.rivetz.stub;

import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;
import com.rivetz.stub.Rivet;
/**
 * Keys can be restrained by key usage rules that enforce the conditions under
 * which they are used. Key usage rules are attached to KeyRecords.
 */
public class KeyUsageRule {
    // Usage rule types are publicly defined in Rivet.java
    Rivet.UsageRule rule;

    public KeyUsageRule(Rivet.UsageRule ruleIn) {
        rule = ruleIn;
    }
    public KeyUsageRule(String ruleStr) {
        rule = Rivet.UsageRule.valueOf(ruleStr);
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
            rule = Rivet.UsageRule.valueOf(json.getString("rule"));
        } catch(JSONException e) {
            Log.e(Utilities.LOG_TAG, "JSON Parse error of KeyUsageRule");
        }
    }
    public JSONObject getJson() {
        JSONObject json = new JSONObject();
        try {
            json.put("rule",rule.toString());
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
            byte[] rule_type = Utilities.int2bytes(Utilities.uint16_t, rule.getValue());

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

        rule = Rivet.UsageRule.values()[new_rule - 1];

        return true;
    }
}
