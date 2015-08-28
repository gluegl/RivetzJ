package com.rivetz.test.json

import groovy.transform.CompileStatic
import org.json.JSONObject

/**
 *
 */
@CompileStatic
@Category(String)
class StringCategory {
    def asType(Class target) {
        if (target==JSONObject) {
            return new JSONObject(this)
        }
        throw new ClassCastException("String cannot be coerced into $target")
    }
}
