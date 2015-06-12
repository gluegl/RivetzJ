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

package com.rivetz.stub;

public class Rivet {
    /**
     * Intent address. This is the component that is targeted to
     * receive the intent
     */
    public static final String RIVET_INTENT		= "com.rivetz.adapter.BRIDGE";

    /**
     * Rivet.Java version
     *
     * The single version number has the following structure:
     * MMNNPP00
     * Major version | Minor version | Patch version
     */
    public static final int RIVETJAVA_VERSION_MAJOR = 0;
    public static final int RIVETJAVA_VERSION_MINOR = 0;
    public static final int RIVETJAVA_VERSION_PATCH = 5;    public static final int    RIVETJAVA_VERSION_NUMBER     = 0x00000500;
    public static final String RIVETJAVA_VERSION		= "0.0.5";
    public static final String RIVETJAVA_VERSION_FULL	= "Rivet.java v0.0.5";

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

    /**
     * Extras provide the parameter data attached to an Intent
     * sent to Rivetz
     */
    public static final String EXTRATYPE_UINT8 = "UINT8";
    public static final String EXTRATYPE_UINT16 = "UINT16";
    public static final String EXTRATYPE_UINT32 = "UINT32";
    public static final String EXTRATYPE_UINT64 = "UINT64";
    public static final String EXTRATYPE_STRING = "STRING";
    public static final String EXTRATYPE_BOOLEAN = "BOOLEAN";
    public static final String EXTRATYPE_BYTES = "BYTES";
    public static final String EXTRATYPE_HEXSTRING = "HEXSTRING";

    // Extra Name Strings
    public static final String EXTRA_INSTRUCT	= EXTRATYPE_UINT8+"_EXTRA_INSTRUCT";
    public static final String EXTRA_SPID		= EXTRATYPE_STRING+"_EXTRA_SPID";
    public static final String EXTRA_CALLID		= EXTRATYPE_UINT16+"_EXTRA_CALLID";
    public static final String EXTRA_KEYNAME	= EXTRATYPE_STRING+"_EXTRA_KEYNAME";
    public static final String EXTRA_PUB		= EXTRATYPE_STRING+"_EXTRA_PUB";
    public static final String EXTRA_PRV		= EXTRATYPE_STRING+"_EXTRA_PRV";
    public static final String EXTRA_TOPUB		= EXTRATYPE_STRING+"_EXTRA_TOPUB";
    public static final String EXTRA_AMT		= EXTRATYPE_STRING+"_EXTRA_AMT";
    public static final String EXTRA_FEE		= EXTRATYPE_STRING+"_EXTRA_FEE";
    public static final String EXTRA_TRANS		= EXTRATYPE_STRING+"_EXTRA_TRANS";
    public static final String EXTRA_SIGNED		= EXTRATYPE_STRING+"_EXTRA_SIGNED";
    public static final String EXTRA_SIGNDONE	= EXTRATYPE_STRING+"_EXTRA_SIGNDONE";
    public static final String EXTRA_PUBLICDATA	= EXTRATYPE_HEXSTRING+"_EXTRA_PUBLICDATA";
    public static final String EXTRA_SECUREDATA	= EXTRATYPE_HEXSTRING+"_EXTRA_SECUREDATA";
    public static final String EXTRA_KEYTYPE	= EXTRATYPE_UINT16+"_EXTRA_KEYTYPE";
    public static final String EXTRA_COIN		= EXTRATYPE_STRING+"_EXTRA_COIN";
    public static final String EXTRA_COIN_ADDRESS = EXTRATYPE_STRING+"_EXTRA_COIN_ADDRESS";
    public static final String EXTRA_PUBKEY		= EXTRATYPE_STRING+"_EXTRA_PUBKEY";
    public static final String EXTRA_PRVKEY		= EXTRATYPE_STRING+"_EXTRA_PRVKEY";
    public static final String EXTRA_MESSAGE	= EXTRATYPE_STRING+"_EXTRA_MESSAGE";
    public static final String EXTRA_HEXSTRING	= EXTRATYPE_HEXSTRING+"_EXTRA_HEXSTRING";
    public static final String EXTRA_BLOB		= EXTRATYPE_BYTES+"_EXTRA_BLOB";
    public static final String EXTRA_PAYLOAD	= EXTRATYPE_BYTES+"_EXTRA_PAYLOAD";
    public static final String EXTRA_SIGNATURE	= EXTRATYPE_STRING+"_EXTRA_SIGNATURE";
    public static final String EXTRA_RESULTDATA = EXTRATYPE_BYTES+"_EXTRA_RESULTDATA";
    public static final String EXTRA_VERIFIED	= EXTRATYPE_BOOLEAN+"_EXTRA_VERIFIED";
    public static final String EXTRA_SHAREDKEY	= EXTRATYPE_STRING+"_EXTRA_SHAREDKEY";
    public static final String EXTRA_KEY		= EXTRATYPE_STRING+"_EXTRA_KEY";
    public static final String EXTRA_HASH_ALGO	= EXTRATYPE_STRING+"_EXTRA_HASH_ALGO";
    public static final String EXTRA_HASH	    = EXTRATYPE_STRING+"_EXTRA_HASH";
    public static final String EXTRA_SILENT     = EXTRATYPE_BOOLEAN+"_EXTRA_SILENT";
    public static final String EXTRA_USAGERULES = EXTRATYPE_BYTES+"EXTRA_USAGERULES";
    public static final String EXTRA_USAGERULE = EXTRATYPE_UINT16+"EXTRA_USAGERULE";

    /**
     * KeyType provided as enum and int for compatibility
     */
    public enum KeyType {
        UNKNOWN(0x0000),
        ECDH_SHARE_DFLT(0x0001),
        ECDH_ENCRYPT_DFLT(0x0002),
        ECDSA_DFLT(0x0003),
        BITCOIN_DFLT(0x0004),
        VCOIN_CUSTOM(0x0005),
        ECDSA_NISTP256(0x0006);

        private final int value;
        private KeyType(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }
    }

    public static final int KEYTYPE_UNKNOWN = 0x0000;
    public static final int KEYTYPE_ECDH_SHARE_DFLT = 0x0001;
    public static final int KEYTYPE_ECDH_ENCRYPT_DFLT = 0x0002;
    public static final int KEYTYPE_ECDSA_DFLT = 0x0003;
    public static final int KEYTYPE_BITCOIN_DFLT = 0x0004;
    public static final int KEYTYPE_VCOIN_CUSTOM = 0x0005;

    /**
     * Key Usage Rules
     */
    public enum UsageRule {
        SP_IDENTITY_KEY(0x0001),                // Specifies a key as an SP's Identity key. An SP record must have an SP identity
        // key and there can only be one SP identity key. The identity key must also have
        // a contain a RIV_TA_SP_KEY_USE_RULE_LIFETIME_PERMANENT Usage Rule.
        REQUIRE_TUI_CONFIRM(0x0002),            // Specifies the key will not be applied to an operation unless user authorization
        // has been provided through the TUI.
        REQUIRE_SIGNED_REQUEST(0x0003),         // Specifies a valid signature must be provided to authorize use of this key.
        PRIV_KEY_EXPORTABLE(0x0004),            // Specifies the private key can be exported.
        LIFETIME_PERMANENT(0x0005),             // Specifies the key is permanent and can't be deleted from the record.
        DEV_IDENTITY_KEY(0x0006);               // Specifies a key as a Device Identity key.

        private final int value;
        private UsageRule(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }
    }

    /**
     * Hash algorithms
     */
    public static final String HASH_MD2         = "HASH_MD2";
    public static final String HASH_MD5         = "HASH_MD5";
    public static final String HASH_SHA1		= "HASH_SHA1";
    public static final String HASH_SHA256		= "HASH_SHA256";
    public static final String HASH_DOUBLESHA256= "HASH_DOUBLESHA256";
    public static final String HASH_RIPEMD160	= "HASH_RIPEMD160";

    /**
     * ERROR Codes provided as int
     */
    public static final int ERROR_NONE		= 0xFFFFFFFF; // no error - 4 byte error code or use RESULT_OK
    public static final int ERROR_CANCELED		=  0x00000000; // user cancelled intent or use RESULT_CANCELED
    public static final int ERROR_UNKNOWN		=  0x00000001; // uknown - generic error result
    public static final int ERROR_INVALID_SPID	=  0x00000020; // Invalid Service Provider ID
    public static final int ERROR_INVALID_JSON	=  0x00000022; // Invalid JSON passed
    public static final int ERROR_INVALID_COIN	=  0x00000024; // Invalid Coin pased
    public static final int ERROR_INVALID_INSTRUCT  =  0x00000025; // Invalid instruction code given
    public static final int ERROR_INVALID_KEYTYPE	=  0x00000026; // Invalid KEYTYPE passed
    public static final int ERROR_INVALID_KEYNAME	=  0x00000028; // Invalid KEYNAME passed
    public static final int ERROR_MISSING_PARAMETER	=  0x00000029; // A required parameter is missing
    public static final int ERROR_KEYNAME_EXISTS	=  0x0000002A; // KEYNAME already exists when adding or creating a key
    public static final int ERROR_KEYNAME_NOTFOUND	=  0x0000002C; // KEYNAME not found
    public static final int ERROR_LOADING_TA       	=  0x00000030; // Error while loading the TA binary
    public static final int ERROR_OPEN_TA           =  0x00000032; // Error opening TA binary
    public static final int ERROR_VERSION_ERROR     =  0x00000050; // Calling TA Version function failed to return result

    public static String FormatError(int ERROR) {
        return (ERROR < 0 ? "-" : "")+
                "0x"+
                ("00000000" + Integer.toHexString(ERROR).toUpperCase()).substring(Integer.toHexString(ERROR).length());
    }
}
