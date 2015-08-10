/*
* Copyright 2015 Rivetz Corp
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* THE SOFTWARE.
*/

package com.rivetz.bridge;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.RemoteException;

import com.rivetz.lib.CoinUtils;
import com.rivetz.lib.InstructionBuilder;
import com.rivetz.lib.InstructionRecord;
import com.rivetz.lib.KeyRecord;
import com.rivetz.lib.RivetBase;
import com.rivetz.lib.ServiceProviderRecord;
import com.rivetz.lib.Utilities;

import java.util.ArrayList;
import java.util.concurrent.Callable;

/**
 * Instantiate Rivet to send commands to the Rivetz App. Once the binding is accomplished
 * commands such as createKey and sign can be invoked directly. Rivet
 * includes the constants definitions that are used for many of these calls
 * <p>
 * Initialization requires a Service Provider ID and all subsequent calls to the Rivet
 * will reference this SPID. The Service Provider ID needs to be paired with the device
 * in order to be honored. Pairing is a one time event that establishes the Service Provider
 * credentials to the Rivet.
 * <p>
 * Rivetz also supports an Intent based interface where commands can be fired to the
 * RIVET_INTENT handler using one of the INSTRUCT_xxx codes.
 */
public class Rivet extends RivetBase {
    /**
     * Address of the component that is targeted to receive the intent
     */
    public static final String RIVET_INTENT		= "com.rivetz.adapter.BRIDGE";
    /**
     * Address of the component targeted for pairing requests
     */
    public static final String RIVET_PAIR       = "com.rivetz.adapter.PAIR";

    /////////////////////////////////////////////////////////////////////////////////////////
    // Instance Code
    /////////////////////////////////////////////////////////////////////////////////////////

    protected Binder binder;
    private Context context;

    /**
     * Instantiate the Rivet class. The Rivet must be bound to the Rivetz app before
     * calls to the api will go through. The binding is triggered automatically but
     * takes place asynchronously. You can pass in a callback or check {@link #isInitialized}
     * @param context Application context
     * @param spid Service Provider ID
     */
    public Rivet(Context context, String spid) {
        this(context, spid, new Callable() {
            @Override
            public Object call() throws Exception {
                return null;
            }
        });
    }

    /**
     * Instantiate the Rivet class. The Rivet must be bound to the Rivetz app
     * calls to the api will go through. This will trigger automatically, but
     * happens asynchronously. You can pass in a callback or check {@link #isInitialized}
     * @param contextGiven Application context
     * @param spidGiven Service Provider ID
     * @param done Callback method for when the Rivet is ready to be called.
     */
    public Rivet(Context contextGiven, String spidGiven, Callable done) {
        super(spidGiven);
        context = contextGiven;
        if (isInstalled(context)) {
            binder = new Binder(context, done);
        } else {
            status = RivetBase.ERROR_NOT_INSTALLED;
        }
    }

    public static boolean isInstalled(Context context) {
        PackageManager pm = context.getPackageManager();
        try {
            pm.getPackageInfo("com.rivetz.adapter", PackageManager.GET_ACTIVITIES);
            return(true);
        } catch (PackageManager.NameNotFoundException e) {
            return(false);
        }
    }

    /**
     * Returns true if the Rivet has been bound to the Rivetz app and is ready to be
     * invoked.
     * @return boolean
     */
    @Override
    public boolean isInitialized() {
        if (binder.isInitialized()) {
            return true;
        } else {
            status = ERROR_ADAPTER_NOT_INIT;
            return false;
        }
    }
    /**
     * Returns true if the device is paired with this spid
     */
    @Override
    public boolean isPaired() {
        try {
            return binder.api.isPaired(spid);
        } catch(Exception e) {
            status = RivetBase.ERROR_UNKNOWN;
            return false;
        }
    }

    /**
     * Trigger pairing
     *
     * @param activity pointer to a foreground activity
     */
    public void pairDevice(Activity activity) {
        // Pairing establishes the service provider on this device. It creates
        // the key store that will hold the keys created with this SPID
        // If the SPID is already paired, the result will be RESULT_OK. If
        // not the user will be prompted to accept the pairing.
        Intent intent = new Intent(RIVET_PAIR)
                .putExtra(RivetBase.EXTRA_SPID, spid)
                .putExtra(RivetBase.EXTRA_SILENT, true);
        if (intent.resolveActivity(activity.getPackageManager()) != null) {
            activity.startActivityForResult(intent, RivetBase.INSTRUCT_PAIRDEVICE);
        }
    }


    /**
     * In case the connection to Rivetz is lost, you can call reconnect to re-establish
     * the connection withouth losing any other state
     */
    @Override
    public void reconnect() {
        reconnect(new Callable() {
            @Override
            public Object call() throws Exception {
                return null;
            }
        });
    }
    /**
     * In case the connection to Rivetz is lost, you can call reconnect to re-establish
     * the connection withouth losing any other state
     * @param done callback method invoked with the binding is complete
     */
    @Override
    public void reconnect(Callable done) {
        binder = new Binder(context, done);
    }


    @Override
    public int getStatus() throws RemoteException {
        return binder.api.getStatus();
    }

    @Override
    protected byte[] execute(String spid, byte[] instruction) throws RemoteException {
        return binder.api.execute(spid, instruction);
    }

    /**
     * Generate a riveted key
     * @param type indicates the type of the key
     * @param name provides a name for the key which is used to reference it in future calls.
     * @param rules Zero or more usage rules that will be added to the riveted key
     * @return a new KeyRecord or null if there is an error
     */
    @Override
    public KeyRecord createKey(KeyType type, String name, UsageRule...rules) {
        if (!isInitialized()) { return null;}
        InstructionRecord instruct = new InstructionBuilder(this, RivetBase.INSTRUCT_CREATEKEY)
                .addParam(RivetBase.EXTRA_KEYTYPE,type.getValue())
                .addParam(RivetBase.EXTRA_KEYNAME,name)
                .addParam(RivetBase.EXTRA_USAGERULES,rules)
                .prepareData();
        response = send(instruct);
        status = response.status;
        if (response.payload != null && response.spRecord != null) {
            String retKeyName = Utilities.extractString(response.payload,0);
            // todo: signature is only on result data of name
            return response.spRecord.getKey(retKeyName);
        } else {
            return null;
        }
    }

    /**
     * Insert a key into the Rivet
     * @param keyName specifies a name for the key
     * @param publicData public portion of the key in hex format
     * @param securedData private portion of the key in hex format
     * @param rules Zero or more usage rules that will be added to the riveted key
     * @return
     */
    @Override
    public KeyRecord addKey(String keyName, String publicData, String securedData, UsageRule...rules) {
        if (!isInitialized()) { return null;}
        InstructionRecord instruct = new InstructionBuilder(this, RivetBase.INSTRUCT_CREATEKEY)
                .addParam(RivetBase.EXTRA_KEYNAME,keyName)
                .addParam(RivetBase.EXTRA_PUBLICDATA,publicData)
                .addParam(RivetBase.EXTRA_SECUREDATA,securedData)
                .addParam(RivetBase.EXTRA_USAGERULES,rules)
                .prepareData();
        response = send(instruct);
        status = response.status;
        if (response.payload != null && response.spRecord != null) {
            String retKeyName = Utilities.extractString(response.payload,0);
            // todo: signature is only on result data of name
            return response.spRecord.getKey(retKeyName);
        } else {
            return null;
        }
    }

    /**
     * Remove the named key from the service provider record
     * @param keyName name of key to delete
     */
    @Override
    public void deleteKey(String keyName) {
        if (!isInitialized()) { return;}
        InstructionRecord instruct = new InstructionBuilder(this, RivetBase.INSTRUCT_DELETEKEY)
                .addParam(RivetBase.EXTRA_KEYNAME,keyName)
                .prepareData();
        response = send(instruct);
        status = response.status;
    }

    /**
     * Fetches the specified key. If there is a device identity key then this
     * response will be signed and can be fetched from RivetResponse
     * <p>
     * If a signature is not needed one can simply examine the Keys list in the
     * ServiceProviderRecord class
     * @param keyName The name assigned to the key
     * @return a key record or null if none found
     */
    @Override
    public KeyRecord getKey(String keyName) {
        if (!isInitialized()) { return null;}
        InstructionRecord instruct = new InstructionBuilder(this, RivetBase.INSTRUCT_CREATEKEY)
                .addParam(RivetBase.EXTRA_KEYNAME,keyName)
                .prepareData();
        response = send(instruct);
        status = response.status;
        if (response.spRecord != null) {
            // todo: signature is only on result data of pub key
            return response.spRecord.getKey(keyName);
        } else {
            return null;
        }
    }

    /**
     * GETKEYS
     *
     * Get a list of the keys established for the current service provider
     * @return returns list of key records
     */
    @Override
    public ArrayList<KeyRecord> getKeys() {
        // todo: this is workaround for now
        if (!isInitialized()) { return null;}
        try {
            byte[] result = binder.api.getServiceProviderRecord(spid);
            if (result == null) {
                status = binder.api.getStatus();
                return null;
            }
            ServiceProviderRecord spr = new ServiceProviderRecord(result);
            return spr.keys;
        } catch(Exception e) {
            status = ERROR_UNKNOWN;
            return null;
        }
    }

    /**
     * SIGNTXN
     *
     * Sign a bitcoin transaction
     *
     */
    @Override
    public String signTxn(String keyName, String coin, String topub, String amount, String fee, String txn) {
        if (!isInitialized()) { return null;}
        InstructionRecord instruct = new InstructionBuilder(this, RivetBase.INSTRUCT_SIGNTXN)
                .addParam(RivetBase.EXTRA_KEYNAME,keyName)
                .addParam(RivetBase.EXTRA_COIN,coin)
                .addParam(RivetBase.EXTRA_TOPUB, topub)
                .addParam(RivetBase.EXTRA_AMT, amount)
                .addParam(RivetBase.EXTRA_FEE, fee)
                .addParam(RivetBase.EXTRA_TRANS, CoinUtils.getTransactionsFromJson(txn))
                .prepareData();
        response = send(instruct);
        status = response.status;
        if (response.payload != null) {
            return Utilities.extractString(response.payload,0);
            // second return parameter is key name and is ignored here
        } else {
            return null;
        }
    }

    /**
     * SIGN - returns the given blob signed with the named key
     *
     * @param keyName
     * @param payload
     * @return
     */
    @Override
    public String sign(String keyName,byte[] payload) {
        if (!isInitialized()) { return null;}
        InstructionRecord instruct = new InstructionBuilder(this, RivetBase.INSTRUCT_SIGN)
                .addParam(RivetBase.EXTRA_KEYNAME,keyName)
                .addParam(RivetBase.EXTRA_PAYLOAD,payload)
                .prepareData();
        response = send(instruct);
        status = response.status;
        if (response.payload != null) {
            // this is the signature
            return Utilities.extractString(response.payload,0);
            // second return parameter is key name and is ignored here
        } else {
            return null;
        }
    }

    @Override
    public Boolean verify(String keyName,String signature) {
        if (!isInitialized()) { return null;}
        InstructionRecord instruct = new InstructionBuilder(this, RivetBase.INSTRUCT_VERIFY)
                .addParam(RivetBase.EXTRA_KEYNAME,keyName)
                .addParam(RivetBase.EXTRA_SIGNATURE,signature)
                .prepareData();
        response = send(instruct);
        status = response.status;
        if (response.payload != null) {
            // response payload is keyname then verified boolean
            int offset = 0;
            String retKeyName = Utilities.extractString(response.payload,offset);
            offset += keyName.length()+Utilities.uint16_t;
            return response.payload[offset]!=0;
        } else {
            return false;
        }
    }

    @Override
    public String ecdhShared(String keyName,String topub) {
        if (!isInitialized()) { return null;}
        InstructionRecord instruct = new InstructionBuilder(this, RivetBase.INSTRUCT_ECDH_SHARED)
                .addParam(RivetBase.EXTRA_KEYNAME,keyName)
                .addParam(RivetBase.EXTRA_TOPUB,topub)
                .prepareData();
        response = send(instruct);
        status = response.status;
        if (response.payload != null) {
            int offset = 0;
            // result is keyname followed by shared key
            String retKeyName = Utilities.extractString(response.payload,offset);
            offset+= keyName.length()+Utilities.uint16_t;
            return Utilities.extractString(response.payload,offset);
        } else {
            return null;
        }
    }

    /**
     * HASH - Perform a hash on the given payload
     *
     * @param hashAlgo algorithm to be used
     * @param payload payload as byte array or string
     * @return hash string
     */
    @Override
    public String hash(String hashAlgo,byte[] payload) {
        if (!isInitialized()) { return null;}
        InstructionRecord instruct = new InstructionBuilder(this, RivetBase.INSTRUCT_HASH)
                .addParam(RivetBase.EXTRA_HASH_ALGO,hashAlgo)
                .addParam(RivetBase.EXTRA_PAYLOAD,payload)
                .prepareData();
        response = send(instruct);
        status = response.status;
        if (response.payload != null) {
            // this is the hash
            return Utilities.extractString(response.payload,0);
        } else {
            return null;
        }
    }

    /**
     * AES Encrypt
     *
     * Given a key name to use and payload to work on encrypt or decrypt depending
     * on the value of reverse
     * @param keyName name of the key to use
     * @param payload the data to encrypt/descrypt as a byte array or string
     * @param reverse if true then descrypt
     * @return encrypted/decrypted payload
     */
    @Override
    public String AESEncrypt(String keyName, byte[] payload, boolean reverse) {
        if (!isInitialized()) { return null;}
        InstructionRecord instruct = new InstructionBuilder(this,reverse? RivetBase.INSTRUCT_AES_DECRYPT: RivetBase.INSTRUCT_AES_ENCRYPT)
                .addParam(RivetBase.EXTRA_STRING,"CBC")
                .addParam(RivetBase.EXTRA_KEYNAME,keyName)
                .addParam(RivetBase.EXTRA_PAYLOAD,payload)
                .prepareData();
        response = send(instruct);
        status = response.status;
        if (response.payload != null) {
            // this is the result data
            return Utilities.extractString(response.payload,0);
        } else {
            return null;
        }
    }

    /**
     * GETADDRESSS
     *
     * return the key address formatted for the given coin type
     *
     * @param keyName the key to use
     * @param coin defaults to "BTC"
     * @return coin address
     */
    @Override
    public String getAddress(String keyName, String coin) {
        if (!isInitialized()) { return null;}
        InstructionRecord instruct = new InstructionBuilder(this, RivetBase.INSTRUCT_GETADDRESS)
                .addParam(RivetBase.EXTRA_KEYNAME,keyName)
                .addParam(RivetBase.EXTRA_COIN,coin)
                .prepareData();
        response = send(instruct);
        status = response.status;
        if (response.payload != null) {
            // this is the address
            return Utilities.extractString(response.payload,0);
        } else {
            return null;
        }
    }
}
