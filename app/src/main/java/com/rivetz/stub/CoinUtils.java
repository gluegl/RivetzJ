package com.rivetz.stub;

import com.rivetz.stub.Utilities;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.text.DecimalFormat;

/**
 * A collection of functions for handling the details of coin instructions
 */
class CoinUtils {

    public static String getTransactionsFromJson(String str) {
        try {
            return(getTransactionsFromJson(new JSONObject(str)));
        } catch(JSONException e) {
            return null;
        }
    }

    public static String getTransactionsFromJson(JSONObject jObj) {
        String returnStr = "";
        try {
            JSONArray jArr = jObj.getJSONArray("unspent");
            int transactions = jArr.length();
            for (int i = 0; i < transactions; i++) {
                JSONObject trans = (JSONObject) jArr.get(i);
                String tx = (String) trans.get("tx");
                Double amt = Utilities.round(Double.parseDouble((String) trans.get("amount")), 8);
                DecimalFormat df = new DecimalFormat("0.00000000");
                String amtstr = df.format(amt);
                int n = (Integer) trans.get("n");
                int confirmations = (Integer) trans.get("confirmations");
                String script = (String) trans.get("script");
                if (i > 0) returnStr += ",";
                returnStr += "tx=" + tx +
                        "&amt=" + amtstr +
                        "&n=" + Integer.toString(n) +
                        "&confirms=" + Integer.toString(confirmations) +
                        "&script=" + script;
            }
        } catch(JSONException e) {
            return null;
        }
        return returnStr;
    }
}
