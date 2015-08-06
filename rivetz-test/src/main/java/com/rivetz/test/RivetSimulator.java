package com.rivetz.test;

import com.rivetz.lib.KeyRecord;
import com.rivetz.lib.KeyUsageRule;
import com.rivetz.lib.RivetBase;
import com.rivetz.lib.Utilities;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.params.MainNetParams;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;

/**
 * An in-memory simulation of the Rivet/RivetBase for test purposes only.
 * Uses bitcoinj to provide Bitcoin and ECKey functions.
 *
 */
public class RivetSimulator extends RivetBase {
    private final NetworkParameters btcNetParams = MainNetParams.get();
    private Map<String, KeyRecord> keyMap = new HashMap<>();


    public RivetSimulator(String spidGiven) {
        super(spidGiven);
    }

    @Override
    public boolean isInitialized() {
        return false;
    }

    @Override
    public boolean isPaired() {
        return true;
    }

    @Override
    public void reconnect() {

    }

    @Override
    public void reconnect(Callable done) {

    }

    @Override
    public byte[] execute(byte[] instructionRecord) {
        return new byte[0];
    }

    @Override
    public int getStatus() throws Exception {
        return 0;
    }

    @Override
    public byte[] getServiceProviderRecord(String spid) throws Exception {
        return new byte[0];
    }

    @Override
    public byte[] execute(String spid, byte[] instruction) throws Exception {
        return new byte[0];
    }

    @Override
    public boolean isPaired(String spid) throws Exception {
        return true;
    }

    /**
     * TODO: share this code (and other similar methods) with RivetInstructBase in yet another BaseClass?
     * @param type
     * @return
     */
    @Override
    public KeyRecord createKey(RivetBase.KeyType type) {
        return(createKey(type, Utilities.generateName()));
    }

    @Override
    public KeyRecord createKey(KeyType type, String name, UsageRule... rules) {
        KeyRecord keyrec = new KeyRecord(type, name);
        switch(type.getValue()) {
            case RivetBase.KEYTYPE_BITCOIN_DFLT:
            case RivetBase.KEYTYPE_ECDSA_DFLT:
                ECKey key = new ECKey();
                keyrec.publicKey = key.getPubKey();
                keyrec.privateKey = key.getPrivKeyBytes();
                break;

            default:
                throw new IllegalArgumentException("unsupported key type");
        }
        for (UsageRule rule : rules) {
            keyrec.addRule(new KeyUsageRule(rule));
        }
        keyMap.put(keyrec.name, keyrec);
        return keyrec;
    }

    @Override
    public KeyRecord addKey(String publicData, String securedData, UsageRule... rules) {
        return(addKey(Utilities.generateName(),publicData,securedData,rules ));
    }

    @Override
    public KeyRecord addKey(String keyName, String publicData, String securedData, UsageRule... rules) {
        // TODO: I assume that added keys are of type KEYTYPE_UNKNOWN, right?
        throw new UnsupportedOperationException("adding keys unsupported");
    }

    @Override
    public void deleteKey(String keyName) {
        keyMap.remove(keyName);
    }

    @Override
    public KeyRecord getKey(String keyName) {
        return keyMap.get(keyName);
    }

    @Override
    public ArrayList<KeyRecord> getKeys() {
        ArrayList<KeyRecord> keys = new ArrayList<>();
        for (KeyRecord keyrec : keyMap.values()) {
            keys.add(keyrec);
        }
        return keys;
    }

    // TODO: Shouldn't this be more strongly typed?
    @Override
    public String signTxn(String keyName, String coin, String topub, String amount, String fee, String txn) {
        KeyRecord keyrec = keyMap.get(keyName);
        if (!coin.equals("BTC")) {
            throw new IllegalArgumentException("unsupported coin type");
        }
        if (keyrec.type.getValue() != RivetBase.KEYTYPE_BITCOIN_DFLT) {
            throw new IllegalArgumentException("unsupported key type");
        }
        Transaction transaction = new Transaction(btcNetParams);
        // TODO: Check assumption that topub is a Bitcoin address
        Address toAddr;
        try {
            toAddr = new Address(btcNetParams, topub);
        } catch (AddressFormatException e) {
            throw new IllegalArgumentException("invalid bitcoin address");
        }
        Coin amountSatoshis = Coin.valueOf(Integer.parseInt(amount));
        Coin feeSatoshis = Coin.valueOf(Integer.parseInt(fee));
        // TODO: txn is a list of UTXOs in JSON format
        return null;
    }

    // TODO: I'm not sure exactly what this should do, nor if I'm doing it right
    // Also what is the difference between ECDSA_DFLT and BITCOIN_DFLT?
    @Override
    public String sign(String keyName, byte[] payload) {
        KeyRecord keyrec = keyMap.get(keyName);
        ECKey key = ECKey.fromPrivate(keyrec.privateKey);
        Sha256Hash hash;
        ECKey.ECDSASignature ecSig;
        byte[] binSig;

        switch(keyrec.type) {

            case BITCOIN_DFLT:
                // Bitcoinish signing
                hash = Sha256Hash.twiceOf(payload);
                ecSig = key.sign(hash);
                TransactionSignature txSig = new TransactionSignature(ecSig, Transaction.SigHash.ALL, false);
                binSig = txSig.encodeToBitcoin();
                break;

            case ECDSA_DFLT:
                // Alternate (simpler) signing than Bitcionish
                hash = Sha256Hash.of(payload);
                ecSig = key.sign(hash);
                binSig = ecSig.encodeToDER();
                break;

            default:
                throw new IllegalArgumentException("unsupported key type");
        }
        String sig = Utilities.bytesToHex(binSig);
        return sig;
    }

    @Override
    public String sign(String name, String payload) {
        return sign(name,payload.getBytes());
    }

    /**
     *  Sign a bitcoinj transaction object containing unsigned transactions
     *  Since SimRivet uses bitcoinj, let's add a convenience method
     *  that signs a bitcoinj Transactoin object.
     * @param keyName
     * @param transaction Bitcoinj transaction object
     * @return
     */
    public void signTransaction(String keyName, Transaction transaction) {
        KeyRecord keyrec = keyMap.get(keyName);
        if (keyrec.type.getValue() != RivetBase.KEYTYPE_BITCOIN_DFLT) {
            throw new IllegalArgumentException("unsupported key type");
        }
        // TODO: Sign all unsigned transaction inputs
        throw new UnsupportedOperationException("Unimplemented");
    }

    @Override
    public Boolean verify(String keyName, String signature) {
        return null;
    }

    @Override
    public String ecdhShared(String keyName, String topub) {
        return null;
    }

    @Override
    public String hash(String hashAlgo, byte[] payload) {
        return null;
    }

    @Override
    public String hash(String hashAlgo, String payload) {
        return null;
    }

    @Override
    public String AESEncrypt(String keyName, byte[] payload, boolean reverse) {
        return null;
    }

    @Override
    public String AESEncrypt(String keyName, byte[] payload) {
        return null;
    }

    @Override
    public String AESEncrypt(String keyName, String payload) {
        return null;
    }

    @Override
    public String AESDecrypt(String keyName, byte[] payload) {
        return null;
    }

    @Override
    public String AESDecrypt(String keyName, String payload) {
        return null;
    }

    /**
     * TODO: what about testnet/regtest addresses?
     * TODO: constants for coin types like "BTC"?
     * @param keyName
     * @param coin
     * @return
     */
    @Override
    public String getAddress(String keyName, String coin) {
        KeyRecord keyrec = keyMap.get(keyName);
        int type = keyrec.type.getValue();
        if (coin.equals("BTC") && ((type == RivetBase.KEYTYPE_BITCOIN_DFLT) || (type == RivetBase.KEYTYPE_ECDSA_DFLT))) {
            Address addr = ECKey.fromPublicOnly(keyrec.publicKey).toAddress(btcNetParams);
            return addr.toString();
        }
        return null;
    }

    @Override
    public String getAddress(String keyName) {
        return getAddress(keyName,"BTC");
    }
}
