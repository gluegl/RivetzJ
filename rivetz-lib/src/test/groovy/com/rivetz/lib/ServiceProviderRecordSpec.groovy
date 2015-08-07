package com.rivetz.lib

import org.json.JSONObject
import spock.lang.Ignore
import spock.lang.Specification

class ServiceProviderRecordSpec extends Specification {
    static final String testSpid = "test-spid"
    static final String testName = "test-name"

    def "no-args constructor works"() {
        when:
        def spRecord = new ServiceProviderRecord()

        then:
        spRecord != null
        spRecord.name == ""
        spRecord.spid == ""
        spRecord.logo == null
    }

    def "can construct using JSON with empty keys array"() {
        when:
        JSONObject json = new JSONObject()
        json.put("spid", testSpid)
        json.put("name", testName)
        json.put("keys", [])
        println json
        def spRecord = new ServiceProviderRecord(json)
        println spRecord

        then:
        spRecord != null
        spRecord.name == testName
        spRecord.spid == testSpid
        spRecord.logo == null
    }

    @Ignore("ServiceProviderRecord is broken for this case, @Ignore should be removed and bug fixed?")
    def "can construct using JSON without  keys array"() {
        when:
        JSONObject json = new JSONObject()
        json.put("spid", testSpid)
        json.put("name", testName)
        println json
        def spRecord = new ServiceProviderRecord(json)
        println spRecord

        then:
        spRecord != null
        spRecord.name == testName
        spRecord.spid == testSpid
        spRecord.logo == null
    }

}