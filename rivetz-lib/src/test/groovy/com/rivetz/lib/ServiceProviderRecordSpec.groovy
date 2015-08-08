package com.rivetz.lib

import com.rivetz.test.json.GStringCategory
import com.rivetz.test.json.StringCategory
import org.json.JSONObject
import spock.lang.Ignore
import spock.lang.Specification
import spock.util.mop.Use

@Use([GStringCategory, StringCategory])
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
        def json = "{spid: ${testSpid}, name: ${testName}, keys: []}" as JSONObject
        def spRecord = new ServiceProviderRecord(json)

        then:
        spRecord != null
        spRecord.name == testName
        spRecord.spid == testSpid
        spRecord.logo == null
    }

    @Ignore("ServiceProviderRecord is broken for this case, @Ignore should be removed and bug fixed?")
    def "can construct using JSON without  keys array"() {
        when:
        def json = "{spid: ${testSpid}, name: ${testName}}" as JSONObject
        def spRecord = new ServiceProviderRecord(json)

        then:
        spRecord != null
        spRecord.name == testName
        spRecord.spid == testSpid
        spRecord.logo == null
    }
}