package com.rivetz.lib;

import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Keys can be restrained by key usage rules that enforce the conditions under
 * which they are used. Key usage rules are attached to KeyRecords. Usage rule
 * types are define in Rivet.java
 */
public class KeyUsageRule {
    private static final Logger log = LoggerFactory.getLogger(KeyUsageRule.class);
    RivetBase.UsageRule mRule;

    /**
     *
     * @param rule
     */
    public KeyUsageRule(RivetBase.UsageRule rule) {
        mRule = rule;
    }
    public KeyUsageRule(String ruleStr) {
        mRule = RivetBase.UsageRule.valueOf(ruleStr);
    }
    public KeyUsageRule(JSONObject json) {
        parseJson(json);
    }
    public KeyUsageRule(byte[] bytes) {
        if (!Deserialize(bytes)) {
            log.error("byte[] Parse error of KeyUsageRule");
        }
    }

    public void parseJson(JSONObject json) {
        try {
            mRule = RivetBase.UsageRule.valueOf(json.getString("mRule"));
        } catch(JSONException e) {
            log.error("JSON Parse error of KeyUsageRule");
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
            log.error("byte write error of KeyUsageRule");
            return null;
        }
    }

    public boolean Deserialize(byte[] bytedata) {
        if (Utilities.uint16_t != bytedata.length) return false;
        int new_rule = Utilities.bytes2int(bytedata,Utilities.uint16_t);
        log.debug("ParseTest KeyUsageRule Type = " + String.valueOf(new_rule));
        if (new_rule <= 0 || new_rule > RivetBase.UsageRule.values().length) return false;

        mRule = RivetBase.UsageRule.values()[new_rule - 1];

        return true;
    }
}
