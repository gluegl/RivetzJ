package com.rivetz.test.json

import groovy.transform.CompileStatic
import org.json.JSONObject

/**
 *
 */
@CompileStatic
@Category(GString)
class GStringCategory {
    def asType(Class target) {
        if (target==JSONObject) {
            return new JSONObject(this.toString())
        }
        throw new ClassCastException("GString cannot be coerced into $target")
    }
}
