package com.rivetz.lib

import spock.lang.Specification

class UtilitiesSpec extends Specification {

    def "can convert zero-length hex string to bytes"() {
        when:
        def bytes = Utilities.hexToBytes("")

        then:
        bytes.length == 0
    }

    def "can convert 1-byte hex string to bytes"() {
        when:
        def bytes = Utilities.hexToBytes("AA")

        then:
        bytes[0] == (byte) 0xAA
    }

    def "can convert 2-byte hex string to bytes"() {
        when:
        def bytes = Utilities.hexToBytes("AABB")

        then:
        bytes == [0xAA, 0xBB] as byte[]
    }

}