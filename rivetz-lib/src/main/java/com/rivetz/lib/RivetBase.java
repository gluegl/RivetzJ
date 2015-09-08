package com.rivetz.lib;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;

/**
 * Abstract Base Class for Rivet(Android) and RivetSimulator.
 */
public abstract class RivetBase {
    /**
     * Use the Developer SPID to experiment with Rivetz before establishing your own SPID.
     * Applications built with the developer SPID have distribution limitations and also
     * won't present your own identity information to the end user.
     */
    public static final String DEVELOPER_SPID = "029d785242baad9f3d7bedcfca29d5391b3c247a3d4eaf5c3a0a5edd9489d1fcad";
    /**
     * The single version number has the following structure:
     * MMNNPP00
     * Major version . Minor version . Patch version
     */
    public static final String RIVETJAVA_VERSION		= "0.9.1";
    /**
     * Instruction codes
     */
    public static final int INSTRUCT_PAIRDEVICE         = 0001; // Get Pointer
    public static final int INSTRUCT_REGISTERPROVIDER   = 0002; // Service provider pairs with device
    public static final int INSTRUCT_EXECUTE	        = 0003; // Execute a server signed instruction
    public static final int INSTRUCT_GETVERSION         = 0004; // Get TA Version Information
    public static final int INSTRUCT_CHECKUPDATE        = 0005; // Check with Intercede for a TA update
    // Request Codes: Service Provider key functionality for storing keys in RivetAndroid
    public static final int INSTRUCT_ADDKEY             = 1001; // Add Key (not secure since key is loaded from Normal World)
    public static final int INSTRUCT_GETKEY             = 1002; // Get Key
    public static final int INSTRUCT_DELETEKEY          = 1003; // Delete a Key
    public static final int INSTRUCT_KEYENUM            = 1004; // Get Next Key Enumerating through them.
    public static final int INSTRUCT_GETIDENTITYKEY     = 1005; // Get Device Identity Key
    public static final int INSTRUCT_GETSPKEY           = 1006; // Get Sevice Provider Key
    // Request Codes: Crypto
    public static final int INSTRUCT_CREATEKEY          = 2001; // Create a ECDSA Key pair to keyname
    public static final int INSTRUCT_SIGN               = 2002; // Create ECDSA Signature from keyname
    public static final int INSTRUCT_VERIFY             = 2003; // Verify a signature from keyname
    public static final int INSTRUCT_ENCRYPT            = 2004; // Encrypted Data using ECDH
    public static final int INSTRUCT_DECRYPT            = 2005; // Decrypt Data using ECDH
    // Request Codes: Coin Specific Crypto
    public static final int INSTRUCT_GETADDRESS         = 3001; // Extract a coin public address out of keyname
    public static final int INSTRUCT_SIGNTXN            = 3002; // Sign a bitcoin transaction
    public static final int INSTRUCT_GETPUBSIG          = 3003; // Extract public key out of message & signature (SECP256K1 curve only)
    // Request Codes: ECDH
    public static final int INSTRUCT_ECDH_SHARED        = 4001; // Shared Key between similiar curve ECDH keys
    // Request Codes: HASH
    public static final int INSTRUCT_HASH               = 5001; // Get a hash result
    // Request Codes: AES
    public static final int INSTRUCT_AES_ENCRYPT        = 6001; // Encrypted Data using AES (not secure exposed key)
    public static final int INSTRUCT_AES_DECRYPT        = 6002; // Decrypt Data using AES (not secure exposed key)
    // Type data the determines how to interpret parameters passed to an intent as an extra
    public static final String EXTRATYPE_UINT8 = "UINT8";
    public static final String EXTRATYPE_UINT16 = "UINT16";
    public static final String EXTRATYPE_UINT32 = "UINT32";
    public static final String EXTRATYPE_UINT64 = "UINT64";
    public static final String EXTRATYPE_STRING = "STRING";
    public static final String EXTRATYPE_BOOLEAN = "BOOLEAN";
    public static final String EXTRATYPE_BYTES = "BYTES";
    public static final String EXTRATYPE_HEXSTRING = "HEXSTRING";
    // Extra Name Strings
    public static final String EXTRA_INSTRUCT	= EXTRATYPE_UINT8 +"_EXTRA_INSTRUCT";
    public static final String EXTRA_SPID		= EXTRATYPE_STRING +"_EXTRA_SPID";
    public static final String EXTRA_CALLID		= EXTRATYPE_UINT16 +"_EXTRA_CALLID";
    public static final String EXTRA_KEYNAME	= EXTRATYPE_STRING +"_EXTRA_KEYNAME";
    public static final String EXTRA_PUB		= EXTRATYPE_STRING +"_EXTRA_PUB";
    public static final String EXTRA_PRV		= EXTRATYPE_STRING +"_EXTRA_PRV";
    public static final String EXTRA_TOPUB		= EXTRATYPE_STRING +"_EXTRA_TOPUB";
    public static final String EXTRA_AMT		= EXTRATYPE_STRING +"_EXTRA_AMT";
    public static final String EXTRA_FEE		= EXTRATYPE_STRING +"_EXTRA_FEE";
    public static final String EXTRA_TRANS		= EXTRATYPE_STRING +"_EXTRA_TRANS";
    public static final String EXTRA_SIGNED		= EXTRATYPE_STRING +"_EXTRA_SIGNED";
    public static final String EXTRA_SIGNDONE	= EXTRATYPE_STRING +"_EXTRA_SIGNDONE";
    public static final String EXTRA_PUBLICDATA	= EXTRATYPE_HEXSTRING +"_EXTRA_PUBLICDATA";
    public static final String EXTRA_SECUREDATA	= EXTRATYPE_HEXSTRING +"_EXTRA_SECUREDATA";
    public static final String EXTRA_KEYTYPE	= EXTRATYPE_UINT16 +"_EXTRA_KEYTYPE";
    public static final String EXTRA_COIN		= EXTRATYPE_STRING +"_EXTRA_COIN";
    public static final String EXTRA_COIN_ADDRESS = EXTRATYPE_STRING +"_EXTRA_COIN_ADDRESS";
    public static final String EXTRA_PUBKEY		= EXTRATYPE_STRING +"_EXTRA_PUBKEY";
    public static final String EXTRA_PRVKEY		= EXTRATYPE_STRING +"_EXTRA_PRVKEY";
    public static final String EXTRA_MESSAGE	= EXTRATYPE_STRING +"_EXTRA_MESSAGE";
    public static final String EXTRA_STRING	= EXTRATYPE_STRING +"_EXTRA_STRING";
    public static final String EXTRA_HEXSTRING	= EXTRATYPE_HEXSTRING +"_EXTRA_HEXSTRING";
    public static final String EXTRA_BLOB		= EXTRATYPE_BYTES +"_EXTRA_BLOB";
    public static final String EXTRA_PAYLOAD	= EXTRATYPE_BYTES +"_EXTRA_PAYLOAD";
    public static final String EXTRA_SIGNATURE	= EXTRATYPE_HEXSTRING +"_EXTRA_SIGNATURE";
    public static final String EXTRA_RESULTDATA = EXTRATYPE_BYTES +"_EXTRA_RESULTDATA";
    public static final String EXTRA_VERIFIED	= EXTRATYPE_BOOLEAN +"_EXTRA_VERIFIED";
    public static final String EXTRA_SHAREDKEY	= EXTRATYPE_STRING +"_EXTRA_SHAREDKEY";
    public static final String EXTRA_KEY		= EXTRATYPE_STRING +"_EXTRA_KEY";
    public static final String EXTRA_HASH_ALGO	= EXTRATYPE_STRING +"_EXTRA_HASH_ALGO";
    public static final String EXTRA_HASH	    = EXTRATYPE_STRING +"_EXTRA_HASH";
    public static final String EXTRA_SILENT     = EXTRATYPE_BOOLEAN +"_EXTRA_SILENT";
    public static final String EXTRA_USAGERULES = EXTRATYPE_BYTES +"EXTRA_USAGERULES";
    public static final String EXTRA_USAGERULE = EXTRATYPE_UINT16 +"EXTRA_USAGERULE";
    public static final int KEYTYPE_UNKNOWN = 0x0000;
    public static final int KEYTYPE_ECDH_SHARE_DFLT = 0x0001;
    public static final int KEYTYPE_ECDH_ENCRYPT_DFLT = 0x0002;
    public static final int KEYTYPE_ECDSA_DFLT = 0x0003;
    public static final int KEYTYPE_BITCOIN_DFLT = 0x0004;
    public static final int KEYTYPE_VCOIN_CUSTOM = 0x0005;
    public static final int KEYTYPE_ECDSA_NISTP256 = 0x0006;
    public static final int KEYTYPE_COIN_BITCOIN_TEST = 0x0007;
    public static final int KEYTYPE_COIN_LITECOIN = 0x0008;
    public static final int KEYTYPE_COIN_PEERCOIN = 0x0009;
    // Hash algorithms
    public static final String HASH_MD2         = "HASH_MD2";
    public static final String HASH_MD5         = "HASH_MD5";
    public static final String HASH_SHA1		= "HASH_SHA1";
    public static final String HASH_SHA256		= "HASH_SHA256";
    public static final String HASH_DOUBLESHA256= "HASH_DOUBLESHA256";
    public static final String HASH_RIPEMD160	= "HASH_RIPEMD160";
    // ERROR Codes provided as int
    public static final int ERROR_NONE                  =  0xFFFFFFFF; // no error - 4 byte error code or use RESULT_OK
    public static final int ERROR_CANCELED              =  0x00000000; // user cancelled intent or use RESULT_CANCELED
    public static final int ERROR_UNKNOWN               =  0x00000001; // uknown - generic error result
    public static final int ERROR_INVALID_SPID          =  0x00000020; // Invalid Service Provider ID
    public static final int ERROR_INVALID_SPNAME        =  0x00000021; // Invalid Service Provider Name
    public static final int ERROR_INVALID_JSON          =  0x00000022; // Invalid JSON passed
    public static final int ERROR_INVALID_COIN          =  0x00000024; // Invalid Coin pased
    public static final int ERROR_INVALID_INSTRUCT      =  0x00000025; // Invalid instruction code given
    public static final int ERROR_INVALID_KEYTYPE       =  0x00000026; // Invalid KEYTYPE passed
    public static final int ERROR_INVALID_KEYNAME       =  0x00000028; // Invalid KEYNAME passed
    public static final int ERROR_MISSING_PARAMETER     =  0x00000029; // A required parameter is missing
    public static final int ERROR_KEYNAME_EXISTS        =  0x0000002A; // KEYNAME already exists when adding or creating a key
    public static final int ERROR_KEYNAME_NOTFOUND      =  0x0000002C; // KEYNAME not found
    public static final int ERROR_DEVICEID_NOTFOUND     =  0x0000002D; // SPR doesnt have a _DEVICEID record
    public static final int ERROR_LOADING_TA            =  0x00000030; // Error while loading the TA binary
    public static final int ERROR_OPEN_TA               =  0x00000032; // Error opening TA binary
    public static final int ERROR_VERSION_ERROR         =  0x00000050; // Calling TA Version function failed to return result
    public static final int ERROR_CORRUPT_SP_RCRD       =  0x00000051; // The serivice provider record signature could not be verified.
    public static final int ERROR_SPID_ALREADY_PAIRED   =  0x00000052; // Attempt to pair a spid that is already paired
    public static final int ERROR_NETWORK_UNAVAILABLE   =  0x00000053; // Unable to connect to network resources
    public static final int ERROR_REGISTER_SP_FAILED    =  0x00000054; // registration of the SPR was rejected by TA
    public static final int ERROR_REGISTER_DEV_FAILED   =  0x00000055; // registration of the device was rejected by RivetzNet
    public static final int ERROR_PAIR_SP_FAILED              =  0x00000056; // pairing of sp with device failed at Rivetz.net
    public static final int ERROR_ADAPTER_NOT_INIT      =  0x00000061; // The rivet adapter is not initialized
    public static final int ERROR_UNKNOWN_TYPE          =  0x00000062;   // Unknown extra or unknown extra data type
    public static final int ERROR_NOT_INSTALLED         =  0x00000063; // The Rivetz app is not installed
    public static final int ERROR_TCI_INVALID           =  0x00000101; // TA communication structure no properly initialized
    public static final int ERROR_INVALID_RESPONSE      =  0x00000103; // TA returned an invalid responseID
    public static final int ERROR_INVALID_CODE          =  0x00000105; // TA returned an invalid returnCode
    public static final int ERROR_INVALID_INSTRUCTION   =  0x00000107; // Execute received an invalid instruction
    public static final int ERROR_TA_NO_RESPONSE        =  0x00000109; // TA did not return a response
    public static final int ERROR_TA_BUFFER_OVERFLOW    =  0x0000010A; // TA returned data larger than expected
    /**
     * Static mapping of error coded to string values
     * Note: this implementation intentionally avoids the String resource file
     * so as not to introduce any context requirements
     */
    protected static final Map<Integer,String> strings;
    static {
        Map<Integer,String> map = new HashMap<>();

        map.put(ERROR_NONE,"Success");
        map.put(ERROR_CANCELED,"Request has been cancelled");
        map.put(ERROR_UNKNOWN,"unknown - generic error result");
        map.put(ERROR_INVALID_SPID,"Invalid Service Provider ID");
        map.put(ERROR_INVALID_SPNAME,"Invalid Service Provider Name");
        map.put(ERROR_INVALID_JSON,"Invalid JSON passed");
        map.put(ERROR_INVALID_COIN,"Invalid Coin pased");
        map.put(ERROR_INVALID_INSTRUCT,"Invalid instruction code given");
        map.put(ERROR_INVALID_KEYTYPE,"Invalid KEYTYPE passed");
        map.put(ERROR_INVALID_KEYNAME,"Invalid KEYNAME passed");
        map.put(ERROR_MISSING_PARAMETER,"A required parameter is missing");
        map.put(ERROR_KEYNAME_EXISTS,"KEYNAME already exists when adding or creating a key");
        map.put(ERROR_KEYNAME_NOTFOUND,"KEYNAME not found");
        map.put(ERROR_DEVICEID_NOTFOUND,"Service Provider record doesn't have a device ID assigned");
        map.put(ERROR_LOADING_TA,"Error loading the TA binary");
        map.put(ERROR_OPEN_TA,"Error opening TA binary");
        map.put(ERROR_SPID_ALREADY_PAIRED,"Service provider is already paired");
        map.put(ERROR_NETWORK_UNAVAILABLE,"There seems to be a problem connecting with the network.");
        map.put(ERROR_REGISTER_SP_FAILED,"Unable to register the service provider with this device");
        map.put(ERROR_REGISTER_DEV_FAILED,"Registration of device with Rivetz.net has failed");
        map.put(ERROR_PAIR_SP_FAILED,"Unable to pair the device with the service provider");
        map.put(ERROR_VERSION_ERROR,"Calling TA Version function failed to return result");
        map.put(ERROR_CORRUPT_SP_RCRD,"The serivice provider record signature could not be verified");
        map.put(ERROR_UNKNOWN_TYPE, "Unknown extra or unknown extra data type");
        map.put(ERROR_TCI_INVALID,"TA communication structure no properly initialized");
        map.put(ERROR_INVALID_RESPONSE,"TA returned an invalid responseID");
        map.put(ERROR_INVALID_CODE, "TA returned an invalid returnCode");
        map.put(ERROR_INVALID_INSTRUCTION,"Execute received an invalid instruction");
        map.put(ERROR_NOT_INSTALLED,"Rivetz is not installed");
        map.put(ERROR_TA_NO_RESPONSE,"TA did not return a response");
        map.put(ERROR_TA_BUFFER_OVERFLOW,"TA returned data larger than expected");

        strings = Collections.unmodifiableMap(map);
    }

    /**
     * Rivet.status can be examined to determine the result of the last API call
     */
    public int status = ERROR_NONE;
    /**
     * contains the parsed results of the last API call
     */
    public RivetResponse response;
    protected String spid;

    public RivetBase(String spidGiven) {
        spid = spidGiven;
    }

    /**
     *
     * @param ERROR error code
     * @return formated error string
     */
    public static String FormatError(int ERROR) {
        return (ERROR < 0 ? "-" : "")+
                "0x"+
                ("00000000" + Integer.toHexString(ERROR).toUpperCase()).substring(Integer.toHexString(ERROR).length());
    }

    /**
     * getErrorText will look up a readable string describing the given error
     *
     * @param error The error code to look up
     * @return readable string
     */
    public static String getErrorText(int error) {

        String s = RivetBase.strings.get(error);
        if (s == null) {
            s = "Error description not found";
        }
        return s;
    }

    /**
     * getErrorLabel will return a string corresponding to the given
     * error code representing its programmatic label. For example, pass
     * in Rivet.ERROR_NONE and get back "ERROR_NONE";
     * @param error the error code to look up
     * @return printable label
     */
    public static String getErrorLabel(int error) {
        String result = "Error label not found";
        try {
            for (Field field : RivetBase.class.getFields()) {
                String fieldname = field.getName();
                if (fieldname.matches("^ERROR_.*")) {
                    if (field.getInt(null) == error) {
                        result = fieldname;
                        break;
                    }
                }
            }
        } catch (IllegalAccessException e) {
            //
        }
        return result;
    }

    /**
     * getInstructLabel will return a string corresponding to the given
     * Instruct code representing its programmatic label. For example, pass
     * in Rivet.INSTRUCT_GETKEY and get back "INSTRUCT_GETKEY";
     * @param instruct the error code to look up
     * @return printable label
     */
    public static String getInstructLabel(int instruct) {
        String result = "Instruct label not found";
        try {
            for (Field field : RivetBase.class.getFields()) {
                String fieldname = field.getName();
                if (fieldname.matches("^INSTRUCT_.*")) {
                    if (field.getInt(null) == instruct) {
                        result = fieldname;
                        break;
                    }
                }
            }
        } catch (IllegalAccessException e) {
            //
        }
        return result;
    }

    abstract public boolean isInitialized();

    abstract public boolean isPaired();

    abstract public void reconnect();

    abstract public void reconnect(Callable done);

    // These 2 methods correspond to IRivetzAPI.aidl
    // and call through to the via the binder.
    abstract public int getStatus() throws Exception;
    abstract protected byte[] execute(String spid, byte[] instruction) throws Exception;


    /**
     * Pass the given instruction as is into the Rivet. This is used
     * when the instruction needs to carry a signature from the Service Provider. When
     * received by the rivet, the Service Provider Record will be loaded
     * and attached.
     * <p>
     * If the Service Provider Record invoked with this instruction contains key identified
     * with a UsageRule of SP_IDENTITY_KEY, then the result
     * will be signed with this device key.
     * @param instructionBytes binary formatted rivet instruction
     * @return response record that contains the results of the instruction
     */
    public byte[] execute(final byte[] instructionBytes) {
        InstructionRecord instruct = new InstructionRecord(instructionBytes);
        response = send(instruct);
        status = response.status;
        return response.payload;
    }

    /**
     * Sends the instruction to the Rivet.
     *
     * Instructions are built up by instantiating an instance with an instruction
     * type and then adding parameter data, or by providing a fully prepared instruction
     * record to the constructor.
     * @return mRivet response data containing the original bytes and the parsed elements
     */
    protected RivetResponse send(InstructionRecord instructionRecord) {
        try {
            byte[] responseRecord = execute(spid, instructionRecord.getBytes());
            if (responseRecord == null || responseRecord.length == 0) {
                return new RivetResponse(getStatus());
            } else {
                return new RivetResponse(responseRecord);
            }
        } catch(Exception e) {
            return new RivetResponse(RivetBase.ERROR_UNKNOWN);
        }
    }

    /**
     * Generate a riveted key. The key name will be randomly generated and can be
     * found in the RivetResponse
     * @param type indicates the type of the key
     * @return a new KeyRecord or null if there is an error
     */
    public KeyRecord createKey(KeyType type) {
        return(createKey(type, Utilities.generateName()));
    }

    /**
     * Insert a key into the Rivet
     * @param publicData public portion of the key in hex format
     * @param securedData private portion of the key in hex format
     * @param rules Zero or more usage rules that will be added to the riveted key
     * @return
     */
    public KeyRecord addKey(String publicData, String securedData, UsageRule...rules) {
        return(addKey(Utilities.generateName(),publicData,securedData,rules ));
    }

    /**
     * Generate a riveted key
     * @param type indicates the type of the key
     * @param name provides a name for the key which is used to reference it in future calls.
     * @param rules Zero or more usage rules that will be added to the riveted key
     * @return a new KeyRecord or null if there is an error
     */
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

    abstract public ArrayList<KeyRecord> getKeys();

    /**
     * SIGNTXN
     *
     * Sign a bitcoin transaction
     *
     */
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
    public byte[] sign(String keyName,byte[] payload) {
        if (!isInitialized()) { return null;}
        InstructionRecord instruct = new InstructionBuilder(this, RivetBase.INSTRUCT_SIGN)
                .addParam(RivetBase.EXTRA_KEYNAME,keyName)
                .addParam(RivetBase.EXTRA_PAYLOAD,payload)
                .prepareData();
        response = send(instruct);
        status = response.status;
        if (response.payload != null) {
            // this is the signature
            return response.payload;
            // second return parameter is key name and is ignored here
        } else {
            return null;
        }
    }

    public byte[] sign(String name, String payload) {
        return sign(name,payload.getBytes());
    }

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

    public String hash(String hashAlgo, String payload) {
        return hash(hashAlgo,payload.getBytes());
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

    public String AESEncrypt(String keyName, byte[] payload) {
        return AESEncrypt(keyName,payload,false);
    }

    public String AESEncrypt(String keyName, String payload) {
        return AESEncrypt(keyName,payload.getBytes(),false);
    }

    public String AESDecrypt(String keyName, byte[] payload) {
        return AESEncrypt(keyName,payload,true);
    }

    public String AESDecrypt(String keyName, String payload) {
        return AESEncrypt(keyName,payload.getBytes(),true);
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

    public String getAddress(String keyName) {
        return getAddress(keyName,"BTC");
    }

    /**
     * KeyType determines the formatting, usage and application of a key
     */
    public enum KeyType {
        /**
         * If KeyType is unknown then you will not be able to use the key. It is a valid
         * option only for raw key records that will be populated later.
         */
        UNKNOWN(0x0000),
        ECDH_SHARE_DFLT(0x0001),
        ECDH_ENCRYPT_DFLT(0x0002),
        ECDSA_DFLT(0x0003),
        BITCOIN_DFLT(0x0004),
        VCOIN_CUSTOM(0x0005),
        ECDSA_NISTP256(0x0006),
        COIN_BITCOIN_TEST(0x0007),
        COIN_LITECOIN(0x0008),
        COIN_PEERCOIN(0x0009);

        private final int value;
        private KeyType(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }
    }

    /**
     * Key Usage Rules
     */
    public enum UsageRule {
        /**
         * Specifies a key as an SP's Identity key. An SP record must have an SP identity
         * key and there can only be one SP identity key. The identity key must also
         * contain a LIFETIME_PERMANENT Usage Rule.
         */
        SP_IDENTITY_KEY(0x0001),
        /**
         * Specifies the key will not be applied to an operation unless user authorization is
         * with a Trusted User Interface confirmation
         */
        REQUIRE_TUI_CONFIRM(0x0002),
        /**
         * Specifies a valid signature must be provided to authorize use of this key.
         */
        REQUIRE_SIGNED_REQUEST(0x0003),
        /**
         * Specifies the private key can be exported. If a key is not exportable it cannot
         * be backed up or cloned to another device.
         */
        PRIV_KEY_EXPORTABLE(0x0004),
        /**
         * Specifies the key is permanent and can't be deleted from the service
         * provider record. To remove the key the entire Service Provider Record
         * must be deleted from the Rivet
         */
        LIFETIME_PERMANENT(0x0005),
        /**
         * Indicates that this is a device identity key which, if present, will be
         * used to sign responses. Each Service Provider will only have a single device
         * identity key.
         */
        DEV_IDENTITY_KEY(0x0006);

        private final int value;
        private UsageRule(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }

        public static int[] getListValues(UsageRule[] rules) {
            int[] rulesList = new int[rules.length];
            int i = 0;
            for (UsageRule rule : rules) {
                rulesList[i++] = rule.getValue();
            }
            return rulesList;
        }
    }
}
