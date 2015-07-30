package com.rivetz.stub;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.Environment;
import android.util.Base64;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;

public class ServiceProviderRecord {	// https://epistery.com/do/view/Main/ServiceProviderRecord
    public int status;
    public enum SignatureUsage {
        SPIDKEY (0x0001),           // The SPR signature was signed using the Identity key of the SP
                                    // and the key's respective signature scheme.
        TA_WRAPPED_HASH(0x0002);    // The SPR signature is a SHA256 hash of the data to be signed wrapped
                                    // into a secure object by the platform's wrapping function.

        private final int value;
        private SignatureUsage(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }
    }

    public String spid;			        // https://epistery.com/do/view/Main/ServiceProviderID
	public String name;                 // https://epistery.com/do/view/Main/ServiceProviderName
	public byte[] logo;			        // https://epistery.com/do/view/Main/ServiceProviderLogo
    public Bitmap logoBmp;
    public SignatureUsage sigusage = SignatureUsage.TA_WRAPPED_HASH;     //
	public byte[] signature;	        // https://epistery.com/do/view/Main/SPRecordSignature
                                        // Note, signature includes the signature header bytes
	public ArrayList<KeyRecord> keys;	// https://epistery.com/do/view/Main/KeyRecord

    public static final int KEY_RCRD_HRD_VERSION_01         = 0x0001;
    public static final int SIG_USAGE_KEY_SPIDKEY           = 0x0001;
    public static final int SIG_USAGE_KEY_TA_WRAPPED_HASH   = 0x0002;
    public static final int sp_logo_image_type_id_value     = 0x0001;
    public static final int SPIDKEY_SIG_DATA_SIZE           = 64;
    public static final int TA_HASH_SIG_DATA_SIZE           = 32;
    public static final int SPID_DATA_VALUE_SIZE            = 33;
    public static final int SP_NAME_DATA_SIZE               = 32;
    public static final int SP_NAME_MIN_DATA_SIZE           = 3;
    public static final int SIG_USAGE_KEY_SIZE              = Utilities.uint16_t;

	public ServiceProviderRecord () {
		spid = "";
		name = "";
        keys = new ArrayList<KeyRecord>();
	}

	public ServiceProviderRecord(String spidGiven) {
		spid = spidGiven;
		name = "";
        keys = new ArrayList<KeyRecord>();
	}

    public ServiceProviderRecord(JSONObject json) {
		parseJson(json);
    }

    public ServiceProviderRecord(byte[] bytes) {
        if (!Deserialize(bytes)) {
            Log.e(Utilities.LOG_TAG, "byte[] Parse error of ServiceProviderRecord");
        }
    }

    public JSONObject getJson() {
		JSONObject json = new JSONObject();
		try {
			json.put("spid", spid);
			json.put("name",name);
            JSONArray jsonKeys = new JSONArray();
            if (keys != null) {
                for (KeyRecord key : keys) {
                    jsonKeys.put(key.getJson());
                }
            }
            json.put("keys",jsonKeys);
        } catch(JSONException e) {
            Log.e(Utilities.LOG_TAG, "JSON write error of ServiceProviderRecord");
            json = null;
		}
		return json;
	}

	@Override
	public String toString() {
		return getJson().toString();
	}

	public void parseJson(JSONObject json) {
		try {
			spid = json.getString("spid");
			name = json.getString("name");
            JSONArray jsonKeys = json.getJSONArray("keys");
            if (jsonKeys != null) {
                keys = new ArrayList<KeyRecord>();
                for (int i = 0; i < jsonKeys.length(); i++) {
                    keys.add(new KeyRecord(jsonKeys.getJSONObject(i)));
                }
            }
		} catch(JSONException e) {
            Log.e(Utilities.LOG_TAG, "JSON Parse error of ServiceProviderRecord");
            spid="";
			name="";
		}
	}

	public boolean parseOnlineJson(JSONObject json) {
		try {
			String status = json.getString("result");
			if (!status.equals("success")) {
				return false;
			}
			name = json.getString("name");
            String logoString = json.getString("logo");
            logo = Base64.decode(logoString,Base64.DEFAULT);
		} catch(JSONException e) {
            Log.e(Utilities.LOG_TAG, "JSON Parse error of ServiceProviderRecord");
			name="";
		}
		return true;
	}

    public Bitmap getLogoBmp() {
        if (logoBmp == null) {
            logoBmp = BitmapFactory.decodeByteArray(logo, 0, logo.length);
        }
        return logoBmp;
    }

	public void parseString(String string) {
		try {
			parseJson(new JSONObject(string));
		} catch(JSONException e) {
            Log.e(Utilities.LOG_TAG, "JSON Parse error of ServiceProviderRecord");
			spid = "";
			name = "";
		}
	}

    /**
     * Render the class data into a serialized stream of bytes
     * @return service provider record as byte array
     */
    public byte[] serialize() {
        try {
            // Build byte array values
            byte[] record_version = Utilities.int2bytes(Utilities.uint16_t, KEY_RCRD_HRD_VERSION_01);
            byte[] spid_data = Utilities.hexToBytes(spid);
            if (spid_data.length != SPID_DATA_VALUE_SIZE ) {
                Log.e(Utilities.LOG_TAG, "SPID Length incorrect while creating ServiceProviderRecord");
                status = Rivet.ERROR_INVALID_SPID;
                return null;
            }
            if (name.length() < SP_NAME_MIN_DATA_SIZE || name.length() > SP_NAME_DATA_SIZE) {
                Log.e(Utilities.LOG_TAG, "SP Name Length incorrect while creating ServiceProviderRecord");
                status = Rivet.ERROR_INVALID_SPNAME;
                return null;
            }
            byte[] length_name_data = Utilities.int2bytes(Utilities.uint16_t, name.length());
            byte[] sp_name = name.getBytes("UTF-8");
            byte[] num_key_records = Utilities.int2bytes(Utilities.uint32_t, keys.size());
            byte[] KeysBytes = new byte[0];
            for (KeyRecord key : keys) {
                KeysBytes = Utilities.bytesconcat(KeysBytes, key.serialize());
            }
            int logolen = logo == null?0:logo.length;
            byte[] sp_logo_image_type_id = Utilities.int2bytes(Utilities.uint16_t, sp_logo_image_type_id_value);
            byte[] size_sp_logo_png_data = Utilities.int2bytes(Utilities.uint32_t, logolen);
            byte[] sig_usage = Utilities.int2bytes(Utilities.uint16_t, sigusage.getValue());
            int siglen = signature == null?0:signature.length;
            byte[] size_sig_data = Utilities.int2bytes(Utilities.uint16_t, siglen);
            int size_signature_info_value = siglen + Utilities.uint16_t + Utilities.uint16_t;
            byte[] size_signature_info = Utilities.int2bytes(Utilities.uint16_t, size_signature_info_value);
            int num_rmng_bytes_in_sp_rcrd_value =
                        record_version.length +
                        size_signature_info.length +
                        spid_data.length +
                        length_name_data.length +
                        sp_name.length +
                        num_key_records.length +
                        KeysBytes.length +
                        sp_logo_image_type_id.length +
                        size_sp_logo_png_data.length +
                        logolen +
                        sig_usage.length +
                        size_sig_data.length +
                        siglen;
            byte[] num_rmng_bytes_in_sp_rcrd = Utilities.int2bytes(Utilities.uint32_t, num_rmng_bytes_in_sp_rcrd_value);
            byte[] retval = new byte[0];
            retval = Utilities.bytesconcat(retval, num_rmng_bytes_in_sp_rcrd);
            retval = Utilities.bytesconcat(retval, record_version);
            retval = Utilities.bytesconcat(retval, size_signature_info);
            retval = Utilities.bytesconcat(retval, spid_data);
            retval = Utilities.bytesconcat(retval, length_name_data);
            retval = Utilities.bytesconcat(retval, sp_name);
            retval = Utilities.bytesconcat(retval, num_key_records);
            if (keys.size() > 0) {
                retval = Utilities.bytesconcat(retval, KeysBytes);
            }
            retval = Utilities.bytesconcat(retval, sp_logo_image_type_id);
            retval = Utilities.bytesconcat(retval, size_sp_logo_png_data);
            if (logolen > 0) {
                retval = Utilities.bytesconcat(retval, logo);
            }
            retval = Utilities.bytesconcat(retval, sig_usage);
            retval = Utilities.bytesconcat(retval, size_sig_data);
            if (siglen > 0) {
                retval = Utilities.bytesconcat(retval, signature);
            }
            return retval;
        } catch(Exception  e) {
            Log.e(Utilities.LOG_TAG, "general error of ServiceProviderRecord");
            return null;
        }
    }

    /**
     * Load the service provider record from a a serialized stream of bytes
     * @param bytedata byte array of a service provider data
     * @return returns true if the parsing succeeds, otherwise false.
     */
    public boolean Deserialize(byte[] bytedata) {
        int Offset = 0;
        byte[] remaining_rcrd_bytes = Utilities.bytesofbytes(bytedata,Offset,Utilities.uint32_t);
        Offset += Utilities.uint32_t;
        int remaining_rcrd_value = Utilities.bytes2int(remaining_rcrd_bytes,Utilities.uint32_t);
        Log.d(Utilities.LOG_TAG, "ParseTest SP Record Remaining Bytes = " + String.valueOf(remaining_rcrd_value));
        if (remaining_rcrd_value != bytedata.length - Utilities.uint32_t) return false;

        byte[] record_version = Utilities.bytesofbytes(bytedata,Offset,Utilities.uint16_t);
        Offset += Utilities.uint16_t;
        int new_record_version_value = Utilities.bytes2int(record_version,Utilities.uint16_t);
        Log.d(Utilities.LOG_TAG, "ParseTest SP Record Version = " + String.valueOf(new_record_version_value));
        if (new_record_version_value != KEY_RCRD_HRD_VERSION_01) return false;

        byte[] size_signature_info = Utilities.bytesofbytes(bytedata,Offset,Utilities.uint16_t);
        Offset += Utilities.uint16_t;
        int size_signature_info_value = Utilities.bytes2int(size_signature_info,Utilities.uint16_t);
        Log.d(Utilities.LOG_TAG, "ParseTest SP Record size_signature_info_value = " + String.valueOf(size_signature_info_value));

        byte[] new_spid_data = Utilities.bytesofbytes(bytedata,Offset,SPID_DATA_VALUE_SIZE);
        Offset += SPID_DATA_VALUE_SIZE;
        String new_spid = Utilities.bytesToHex(new_spid_data);
        Log.d(Utilities.LOG_TAG, "ParseTest SP Record SPID = " + String.valueOf(new_spid));

        byte[] length_name_data = Utilities.bytesofbytes(bytedata,Offset,Utilities.uint16_t);
        Offset += Utilities.uint16_t;
        int new_length_name_data = Utilities.bytes2int(length_name_data,Utilities.uint16_t);
        Log.d(Utilities.LOG_TAG, "ParseTest SP Name Length = " + String.valueOf(new_length_name_data));

        byte[] new_name_data = Utilities.bytesofbytes(bytedata,Offset,new_length_name_data);
        Offset += new_length_name_data;

        String new_name;
        try {
            new_name = new String(new_name_data, "UTF-8");
        }
        catch (UnsupportedEncodingException e) {
            Log.e(Utilities.LOG_TAG, "byte[] Parse error of ServiceProviderRecord");
            return false;
        }
        Log.d(Utilities.LOG_TAG, "ParseTest SP Name = " + new_name);

        byte[] num_key_records = Utilities.bytesofbytes(bytedata,Offset,Utilities.uint32_t);
        Offset += Utilities.uint32_t;
        int new_num_key_records = Utilities.bytes2int(num_key_records,Utilities.uint32_t);
        Log.d(Utilities.LOG_TAG, "ParseTest SP Number of Keys = " + String.valueOf(new_num_key_records));

        ArrayList<KeyRecord> new_key_records = new ArrayList<KeyRecord>();
        for (int OnKeyRecord = 0; OnKeyRecord < new_num_key_records; OnKeyRecord++) {
            byte[] new_remaining_rcrd_bytes = Utilities.bytesofbytes(bytedata,Offset,Utilities.uint16_t);
            int new_remaining_rcrd_value = Utilities.bytes2int(new_remaining_rcrd_bytes,Utilities.uint16_t);
            Log.d(Utilities.LOG_TAG, "ParseTest Key Number of Remaining Bytes = " + String.valueOf(new_remaining_rcrd_value));

            byte[] new_key_data = Utilities.bytesofbytes(bytedata,Offset,new_remaining_rcrd_value + Utilities.uint16_t);
            Offset += new_remaining_rcrd_value + Utilities.uint16_t;

            new_key_records.add(new KeyRecord(new_key_data));
        }

        byte[] new_sp_logo_image_type_id = Utilities.bytesofbytes(bytedata,Offset,Utilities.uint16_t);
        Offset += Utilities.uint16_t;
        int new_sp_logo_image_type_id_value = Utilities.bytes2int(new_sp_logo_image_type_id,Utilities.uint16_t);
        Log.d(Utilities.LOG_TAG, "ParseTest SP logo type = " + String.valueOf(new_sp_logo_image_type_id_value));
        if (new_sp_logo_image_type_id_value != sp_logo_image_type_id_value) return false;

        byte[] new_size_sp_logo_png_data = Utilities.bytesofbytes(bytedata,Offset,Utilities.uint32_t);
        Offset += Utilities.uint32_t;
        int new_size_sp_logo_png_value = Utilities.bytes2int(new_size_sp_logo_png_data,Utilities.uint32_t);
        Log.d(Utilities.LOG_TAG, "ParseTest SP logo length = " + String.valueOf(new_size_sp_logo_png_value));

        byte[] new_logo = Utilities.bytesofbytes(bytedata,Offset,new_size_sp_logo_png_value);
        Offset += new_size_sp_logo_png_value;

        byte[] new_sig_usage = Utilities.bytesofbytes(bytedata,Offset,Utilities.uint16_t);
        Offset += Utilities.uint16_t;
        int new_sig_usage_value = Utilities.bytes2int(new_sig_usage,Utilities.uint16_t);
        Log.d(Utilities.LOG_TAG, "ParseTest SP Record sig_usage = " + String.valueOf(new_sig_usage_value));
        if (new_sig_usage_value <= 0 || new_sig_usage_value > SignatureUsage.values().length) return false;

        byte[] signature_size = Utilities.bytesofbytes(bytedata,Offset,Utilities.uint16_t);
        Offset += Utilities.uint16_t;
        int signature_size_value = Utilities.bytes2int(signature_size,Utilities.uint16_t);
        Log.d(Utilities.LOG_TAG, "ParseTest SP Record signature_size_value = " + String.valueOf(signature_size_value));
        if (size_signature_info_value != (signature_size_value + Utilities.uint16_t + Utilities.uint16_t)) return false;
        Log.d(Utilities.LOG_TAG, "ParseTest SP Record signature sizes are all good.");
        if (new_sig_usage_value == SIG_USAGE_KEY_SPIDKEY && signature_size_value != SPIDKEY_SIG_DATA_SIZE) return false;
        Log.d(Utilities.LOG_TAG, "ParseTest SP Record signature type matches size.");

        byte[] new_signature = Utilities.bytesofbytes(bytedata,Offset,signature_size_value);
        Offset += signature_size_value;

        Log.d(Utilities.LOG_TAG, "ParseTest SP remaining_rcrd = " + String.valueOf(remaining_rcrd_value));
        Log.d(Utilities.LOG_TAG, "ParseTest SP Offset Result = " + String.valueOf(Offset));
        if (remaining_rcrd_value + Utilities.uint32_t != Offset) return false;

        spid = new_spid;
        name = new_name;
        keys =  new ArrayList<KeyRecord>(new_key_records);
        logo = new_logo;
        sigusage = SignatureUsage.values()[new_sig_usage_value - 1];
        signature = new_signature;

        return true;
    }

    /**
     * Test the SPID value for proper formatting
     * @return true/false
     */
    public boolean validate() {
		if (spid == null) return false;
		else if (spid.isEmpty()) return false;
        else if (spid.length()/2 != SPID_DATA_VALUE_SIZE ) return false;
		else return true;
	}

    /**
     * Add a key to the service provider record. NOTE that this method is used for
     * constructing the class and is not useful for adding a real key to the record.
     * Only the Rivet can make changes to a ServiceProviderRecord. Use Rivet.createKey
     * to add a real key.
     * @param key a KeyRecord to insert into the ServiceProviderRecord
     */
    public void addKey(KeyRecord key) {
        if (keys == null) {
            keys = new ArrayList<KeyRecord>();
        }
        keys.add(key);
    }

    /**
     * Delete a key from the service provider record. NOTE that this method is used
     * for superficial class edits and is not useful for deleting a real key from the
     * record. Only the Rivet can make changes to ServiceProviderRecord. Use Rivet.deleteKey
     * @param keyName the name of the key to be deleted.
     */
    public void deleteKey(String keyName) {
        if (keys != null) {
            for (int i=0; i<keys.size();i++) {
                if (keys.get(i).name.equals(keyName)) {
                    keys.remove(i);
                }
            }
        }
    }

    /**
     * Return the KeyRecord identified by the given KeyName
     * @param keyName name of the key
     * @return KeyRecord or Null if not found
     */
    public KeyRecord getKey(String keyName) {
        if (keys != null) {
            for (KeyRecord key : keys) {
                if (key.name.equals(keyName)) {
                    return key;
                }
            }
        }
        return null;
    }
}
