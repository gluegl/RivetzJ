package com.rivetz.lib

import spock.lang.Specification

class KeyRecordSpec extends Specification {

    def "no-args constructor creates empty name, unknown key type"() {
        when:
        def rec = new KeyRecord()

        then:
        rec.name == ""
        rec.type == RivetBase.KeyType.UNKNOWN
    }

    def "two-args constructor sets name and type"() {
        when:
        def rec = new KeyRecord(RivetBase.KeyType.BITCOIN_DFLT, "test key")

        then:
        rec.name == "test key"
        rec.type == RivetBase.KeyType.BITCOIN_DFLT
    }
}