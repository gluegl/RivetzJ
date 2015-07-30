package com.rivetz.stub;

import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONArray;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;


public class KeyRecord {		// https://epistery.com/do/view/Main/KeyRecord

    public Rivet.KeyType type;                    // https://epistery.com/do/view/Main/KeyType
    public String name;                     // https://epistery.com/do/view/Main/KeyName
	public byte[] publicKey;                // https://epistery.com/do/edit/Main/PublicKey
	public byte[] privateKey;               // https://epistery.com/do/edit/Main/PrivateKey
    public ArrayList<KeyUsageRule> rules;   // https://epistery.com/do/edit/Main/KeyUsage

    private static final int record_version_value                 = 0x0001;
    private static final int RIV_TA_SP_KEY_RCRD_KEY_NAME_MAX_SIZE = 128;
    private static final int RIV_TA_SP_KEY_RCRD_KEY_NAME_MIN_SIZE = 1;

    public KeyRecord() {
        name = "";
        type = Rivet.KeyType.UNKNOWN;
    }
    public KeyRecord(String nameGiven) {
        name = nameGiven;
        type = Rivet.KeyType.UNKNOWN;
    }
    public KeyRecord(JSONObject json) {
        parseJson(json);
        if (type == null) {
            type = Rivet.KeyType.UNKNOWN;
        }
    }
    public KeyRecord(byte[] bytes) {
        if (!Deserialize(bytes)) {
            type = Rivet.KeyType.UNKNOWN;
            Log.e(Utilities.LOG_TAG, "byte[] Parse error of KeyRecord");
        }
    }
    public KeyRecord(Rivet.KeyType typeGiven) {
        type = typeGiven;
        name = "";
    }
    public KeyRecord(Rivet.KeyType typeGiven, String nameGiven) {
        type = typeGiven;
        name = nameGiven;
    }

    public JSONObject getJson() {
        JSONObject json = new JSONObject();
        try {
            json.put("name",name);
            json.put("type",type.toString());
            if (publicKey != null) {
                json.put("publicKey", Utilities.bytesToHex(publicKey));
            }
            if (privateKey != null) {
                json.put("privateKey", Utilities.bytesToHex(privateKey));
            }
            JSONArray jsonRules = new JSONArray();
            if (rules != null) {
                for (KeyUsageRule rule : rules) {
                    jsonRules.put(rule.getJson());
                }
            }
            json.put("rules",jsonRules);
        } catch(JSONException e) {
            json = null;
        }
        return json;
    }
    public void parseJson(JSONObject json) {
        try {
            name = json.getString("name");
            // TODO: is keytype in JSON a string or an int?
            type = Rivet.KeyType.valueOf(json.getString("type"));
            publicKey = Utilities.hexToBytes(json.getString("publicKey"));
            privateKey = Utilities.hexToBytes(json.getString("privateKey"));
            JSONArray jsonRules = json.getJSONArray("rules");
            if (jsonRules != null) {
                rules = new ArrayList<KeyUsageRule>();
                for (int i=0; i < jsonRules.length(); i++) {
                    rules.add(new KeyUsageRule(jsonRules.getJSONObject(i)));
                }
            }
        } catch(JSONException e) {
            Log.e(Utilities.LOG_TAG, "JSON Parse error of KeyRecord");
            name="";
        }
    }

    @Override
    public String toString() {
        return getJson().toString();
    }

    public byte[] serialize() {
        try {
            // Build byte array values
            byte[] record_version = Utilities.int2bytes(Utilities.uint16_t, record_version_value);
            byte[] key_type_id = Utilities.int2bytes(Utilities.uint16_t, type.getValue());
            if (name.length() < RIV_TA_SP_KEY_RCRD_KEY_NAME_MIN_SIZE || name.length() > RIV_TA_SP_KEY_RCRD_KEY_NAME_MAX_SIZE) return null;
            byte[] length_name_data = Utilities.int2bytes(Utilities.uint16_t, name.length());
            byte[] key_name = name.getBytes("UTF-8");
            int publickeylen = 0;
            if (publicKey != null) publickeylen = publicKey.length;
            byte[] public_key_len_data = Utilities.int2bytes(Utilities.uint16_t, publickeylen);
            int privatekeylen = 0;
            if (privateKey != null) privatekeylen = privateKey.length;
            byte[] private_key_len_data = Utilities.int2bytes(Utilities.uint16_t, privatekeylen);
            byte[] num_rules = Utilities.int2bytes(Utilities.uint16_t, rules.size());
            byte[] RulesBytes = new byte[0];
            for (KeyUsageRule rule : rules) {
                RulesBytes = Utilities.bytesconcat(RulesBytes, rule.Serialize());
            }

            int remaining_rcrd_bytes_value =
                    record_version.length +
                    key_type_id.length +
                    length_name_data.length +
                    key_name.length +
                    public_key_len_data.length +
                    publickeylen +
                    private_key_len_data.length +
                    privatekeylen +
                    num_rules.length +
                    RulesBytes.length;
            byte[] remaining_rcrd_bytes = Utilities.int2bytes(Utilities.uint16_t, remaining_rcrd_bytes_value);

            // Build Byte Array List
            int recordsize = remaining_rcrd_bytes_value + Utilities.uint16_t;
            byte[] retval = new byte[0];
            retval = Utilities.bytesconcat(retval, remaining_rcrd_bytes);
            retval = Utilities.bytesconcat(retval, record_version);
            retval = Utilities.bytesconcat(retval, key_type_id);
            retval = Utilities.bytesconcat(retval, length_name_data);
            retval = Utilities.bytesconcat(retval, key_name);
            retval = Utilities.bytesconcat(retval, public_key_len_data);
            if (publickeylen > 0) {
                retval = Utilities.bytesconcat(retval, publicKey);
            }
            retval = Utilities.bytesconcat(retval, private_key_len_data);
            if (privatekeylen > 0) {
                retval = Utilities.bytesconcat(retval, privateKey);
            }
            retval = Utilities.bytesconcat(retval, num_rules);
            if (rules.size() > 0) {
                retval = Utilities.bytesconcat(retval, RulesBytes);
            }
            if (recordsize != retval.length) {
                Log.e(Utilities.LOG_TAG, "RecordSize Mismatch KeyRecord");
            }
            return retval;

        } catch(UnsupportedEncodingException e ) {
            Log.e(Utilities.LOG_TAG, "Encoding byte write error of KeyRecord");
            return null;
        } catch(Exception e ) {
            Log.e(Utilities.LOG_TAG, "general error of KeyRecord");
            return null;
        }
    }

    public boolean Deserialize(byte[] bytedata) {
        int Offset = 0;

        byte[] remaining_rcrd_bytes = Utilities.bytesofbytes(bytedata,Offset,Utilities.uint16_t);
        Offset += Utilities.uint16_t;
        int remaining_rcrd_value = Utilities.bytes2int(remaining_rcrd_bytes,Utilities.uint16_t);
        Log.d(Utilities.LOG_TAG, "ParseTest KeyRecord Remaining Bytes = " + String.valueOf(remaining_rcrd_value));
        if (remaining_rcrd_value != bytedata.length - Utilities.uint16_t) return false;

        byte[] record_version = Utilities.bytesofbytes(bytedata,Offset,Utilities.uint16_t);
        Offset += Utilities.uint16_t;
        int new_record_version_value = Utilities.bytes2int(record_version,Utilities.uint16_t);
        Log.d(Utilities.LOG_TAG, "ParseTest KeyRecord Version = " + String.valueOf(new_record_version_value));
        if (new_record_version_value != record_version_value) return false;

        byte[] key_type_id = Utilities.bytesofbytes(bytedata,Offset,Utilities.uint16_t);
        int new_type = Utilities.bytes2int(key_type_id,Utilities.uint16_t);
        Log.d(Utilities.LOG_TAG, "ParseTest KeyRecord Type = " + String.valueOf(new_type));
        if (new_type < 0 || new_type > Rivet.KeyType.values().length) return false;
        Offset += Utilities.uint16_t;

        byte[] length_name_data = Utilities.bytesofbytes(bytedata,Offset,Utilities.uint16_t);
        int length_name = Utilities.bytes2int(length_name_data,Utilities.uint16_t);
        Log.d(Utilities.LOG_TAG, "ParseTest KeyRecord Name Length = " + String.valueOf(length_name));
        if (length_name < RIV_TA_SP_KEY_RCRD_KEY_NAME_MIN_SIZE || length_name > RIV_TA_SP_KEY_RCRD_KEY_NAME_MAX_SIZE) return false;
        Offset += Utilities.uint16_t;

        byte[] new_name_data = Utilities.bytesofbytes(bytedata,Offset,length_name);
        Offset += length_name;
        String new_name;
        try {
            new_name = new String(new_name_data, "UTF-8");
        }
        catch (UnsupportedEncodingException e) {
            Log.e(Utilities.LOG_TAG, "byte[] Parse error of KeyRecord");
            return false;
        }
        Log.d(Utilities.LOG_TAG, "ParseTest KeyRecord Name = " + new_name);

        byte[] public_key_len_data = Utilities.bytesofbytes(bytedata,Offset,Utilities.uint16_t);
        int public_key_len = Utilities.bytes2int(public_key_len_data,Utilities.uint16_t);
        Log.d(Utilities.LOG_TAG, "ParseTest KeyRecord Public Key Length = " + String.valueOf(public_key_len));
        // TODO what is true max size of public key data.   This might not be determined
        // if (public_key_len < 0 || public_key_len > 2048) return false;
        Offset += Utilities.uint16_t;

        byte[] new_publicKey = new byte[0];
        if (public_key_len > 0) {
            new_publicKey = Utilities.bytesofbytes(bytedata,Offset,public_key_len);
            Offset += public_key_len;
        }

        byte[] private_key_len_data = Utilities.bytesofbytes(bytedata,Offset,Utilities.uint16_t);
        int private_key_len = Utilities.bytes2int(private_key_len_data,Utilities.uint16_t);
        // TODO what is true max size of private key data.   This might not be determined
        if (private_key_len < 0 || private_key_len > 2048) return false;
        Offset += Utilities.uint16_t;
        Log.d(Utilities.LOG_TAG, "ParseTest KeyRecord Private Key Length = " + String.valueOf(private_key_len));

        byte[] new_privateKey = new byte[0];
        if (private_key_len > 0) {
            new_privateKey = Utilities.bytesofbytes(bytedata,Offset,private_key_len);
            Offset += private_key_len;
        }

        byte[] num_rules_data = Utilities.bytesofbytes(bytedata,Offset,Utilities.uint16_t);
        int num_rules = Utilities.bytes2int(num_rules_data,Utilities.uint16_t);
        Log.d(Utilities.LOG_TAG, "ParseTest KeyRecord Number of Rules = " + String.valueOf(num_rules));
        Offset += Utilities.uint16_t;

        ArrayList<KeyUsageRule> new_rules = new ArrayList<KeyUsageRule>();
        for (int OnRule = 0; OnRule < num_rules; OnRule++) {
            byte[] rule_data = Utilities.bytesofbytes(bytedata,Offset,Utilities.uint16_t);
            Offset += Utilities.uint16_t;

            new_rules.add(new KeyUsageRule(rule_data));
        }
        Log.d(Utilities.LOG_TAG, "ParseTest KeyRecord Remaining Bytes = " + String.valueOf(remaining_rcrd_value));
        Log.d(Utilities.LOG_TAG, "ParseTest KeyRecord Offset Result = " + String.valueOf(Offset));
        if (remaining_rcrd_value + Utilities.uint16_t != Offset) return false;

        type = Rivet.KeyType.values()[new_type];
        name = new_name;
        publicKey = new_publicKey;
        privateKey = new_privateKey;
        rules =  new ArrayList<KeyUsageRule>(new_rules);

        return true;
    }

    public void addRule(KeyUsageRule rule) {
        if (rules == null) {
            rules = new ArrayList<KeyUsageRule>();
        }
        rules.add(rule);
    }

    public boolean hasRule(Rivet.UsageRule ruleTested) {
        for (KeyUsageRule rule : rules) {
            if (rule.mRule == ruleTested) {
                return true;
            }
        }
        return false;
    }

    public void deleteRule(Rivet.UsageRule ruleType) {
        for (int i=0; i<rules.size();i++) {
            if (rules.get(i).mRule == ruleType) {
                rules.remove(i);
            }
        }
    }

}

