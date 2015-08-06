package com.rivetz.bridge;

import android.os.Build;

/**
 * Android-specific methods extracted from Utilities class that is now in rivetz-lib.
 */
public class AndroidUtilities {

    public static String getDeviceName() {
        String manufacturer = Build.MANUFACTURER;
        String model = ConvertModel(Build.MODEL);
        if (model.startsWith(manufacturer) || manufacturer.length()>16) {
            return capitalize(model);
        } else {
            return capitalize(manufacturer) + " " + model;
        }
    }

    private static String capitalize(String s) {
        if (s == null || s.length() == 0) {
            return "";
        }
        char first = s.charAt(0);
        if (Character.isUpperCase(first)) {
            return s;
        } else {
            return Character.toUpperCase(first) + s.substring(1);
        }
    }
    public static String ConvertModel(String model) {
        if (model.startsWith("SM-N910")) return "Galaxy Note4";
        if (model.startsWith("SM-G925")) return "Galaxy S6 Edge";
        if (model.startsWith("SM-G920")) return "Galaxy S6";
        if (model.startsWith("SM-G900")) return "Galaxy S5";
        if (model.startsWith("SHV-E330")) return "Galaxy S4 LTE";
        if (model.startsWith("SCH-I545")) return "Galaxy S4";
        if (model.startsWith("SGH-I337")) return "Galaxy S4";
        if (model.startsWith("SPH-L720")) return "Galaxy S4";
        if (model.startsWith("SGH-M919")) return "Galaxy S4";
        if (model.startsWith("GT-I930")) return "Galaxy S3";
        if (model.startsWith("N900")) return "Galaxy Note 3";
        if (model.startsWith("SM-N900")) return "Galaxy Note 3";
        if (model.startsWith("GT-N7100")) return "Galaxy Note II";
        if (model.startsWith("GT-N7000")) return "Galaxy Note";
        if (model.startsWith("SM-G386")) return "Galaxy Avant";
        if (model.startsWith("LG-H345")) return "Leon";

        return model;
    }
}
