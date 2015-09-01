import com.rivetz.lib.RivetBase
import com.rivetz.lib.Utilities
import com.rivetz.test.RivetSimulator
import org.bitcoinj.core.Address
import org.bitcoinj.core.ECKey
import org.bitcoinj.core.NetworkParameters
import org.bitcoinj.core.Sha256Hash
import org.bitcoinj.params.MainNetParams
import spock.lang.Shared
import spock.lang.Specification

class RivetSimulatorSpec extends Specification {
    static final NetworkParameters btcNetParams = MainNetParams.get()

    @Shared
    RivetBase rivet

    def setup() {
        rivet = createRivet()
    }

    def "Rivet can be constructed properly by test setup"() {
        expect:
        rivet != null
        rivet.keyMap.size() == 0
    }

    def "Can create a valid Bitcoin key"() {
        when: "We create a Bitcoin key"
        def keyrec = rivet.createKey(RivetBase.KeyType.BITCOIN_DFLT, "testkey")

        then: "KeyRecord fields are initialized properly"
        keyrec.type.value == RivetBase.KEYTYPE_BITCOIN_DFLT;
        keyrec.name == "testkey"
        keyrec.publicKey != null
        keyrec.privateKey != null

        when: "we create an ECKey and Address from KeyRecord private key"
        ECKey key = ECKey.fromPrivate(keyrec.privateKey);
        Address address = key.toAddress(btcNetParams)

        then: "Address is valid"
        address != null

        when: "we create an ECKey and Address from KeyRecord public key"
        key = ECKey.fromPrivate(keyrec.publicKey);
        address = key.toAddress(btcNetParams)

        then: "Address is valid"
        address != null
    }

    def "Can create an ECDSA key and encode with it"() {
        given:
        def keyname = "ecdsa-key"
        def cleartext = "cleartext"
        def keyrec = rivet.createKey(RivetBase.KeyType.ECDSA_DFLT, keyname)

        when: "we sign a transaction using the Rivet"
        def sig = rivet.sign(keyname, "cleartext")

        and: "we create a check signature using bitcoinj"
        def key = ECKey.fromPrivate(keyrec.privateKey)
        def hash = Sha256Hash.of(cleartext.getBytes())
        def checkSig = key.sign(hash).encodeToDER()

        then: "the signature matches"
        sig == checkSig
    }

    def "Can create a Bitcoin key and fetch a valid KeyRecord"() {
        given: "A Bitcoin key inside the Rivet"
        def keyName = "testkey"
        rivet.createKey(RivetBase.KeyType.BITCOIN_DFLT, "testkey")

        when: "We get its KeyRecord"
        def keyrec = rivet.getKey(keyName)

        then: "KeyRecord fields are initialized properly"
        keyrec.type.value == RivetBase.KEYTYPE_BITCOIN_DFLT;
        keyrec.name == "testkey"
        keyrec.publicKey != null
        keyrec.privateKey != null
    }

    def "Can delete a Bitcoin key"() {
        given: "A Bitcoin key inside the Rivet"
        def keyName = "testkey"
        rivet.createKey(RivetBase.KeyType.BITCOIN_DFLT, "testkey")

        when: "We delete it"
        def keyrec = rivet.deleteKey(keyName)

        then: "It can no longer be retrieved"
        rivet.getKey(keyName) == null
    }

    def "Can create a Bitcoin key and fetch a valid address"() {
        given: "A Bitcoin key inside the Rivet"
        def keyName = "testkey"
        def keyrec = rivet.createKey(RivetBase.KeyType.BITCOIN_DFLT, "testkey")

        when: "We get its address "
        def addrString = rivet.getAddress(keyName)
        def addr = new Address(btcNetParams, addrString)

        then: "The address is valid"
        addr != null
    }

    /**
     * This method can be overridden to test other Rivet implementations, e.g. the real one.
     * @return A Rivet instance
     */
    RivetBase createRivet() {
        return new RivetSimulator("spid")
    }
}
