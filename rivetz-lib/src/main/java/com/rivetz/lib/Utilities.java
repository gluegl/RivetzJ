package com.rivetz.lib;

import android.os.Build;

import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.UUID;

/**
 * Common utilities for string and number manipulation
 */
public final class Utilities {
    public static final int uint8_t = 1;
    public static final int uint16_t = 2;
    public static final int uint32_t = 4;
    public static final int uint64_t = 8;

    public static final String LOG_TAG = "RivetAndroid";

    public static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static int hexsize2ToInt(String s) {
        if (s.length() != 2) return -1;
        byte[] bytes = hexToBytes(s);
        if (bytes.length != 1) return -2;
        Byte b = bytes[0];
        return b.intValue();
    }

    public static String bytesToHex(byte[] a) {
        if (a == null) return "";
        StringBuilder sb = new StringBuilder(a.length * 2);
        for (byte b : a)
            sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    public static String asciiToHex(String asciiValue) {
        if (asciiValue == null) return "";
        char[] chars = asciiValue.toCharArray();
        StringBuffer hex = new StringBuffer();
        for (int i = 0; i < chars.length; i++) {
            hex.append(Integer.toHexString((int) chars[i]));
        }
        return hex.toString();
    }

    static String source = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
    static String target = "Q9A8ZWS7XEDC6RFVT5GBY4HNU3J2MI1KO0LPQ9A8ZWS7XEDC6RFVT5GBY4HNU3";

    public static String obfuscate(String s) {
        char[] result = new char[10];
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            int index = source.indexOf(c);
            result[i] = target.charAt(index);
        }

        return new String(result);
    }

    public static String generateName() {
        return(UUID.randomUUID().toString().replaceAll("-", ""));
    }

    public static String unobfuscate(String s) {
        char[] result = new char[10];
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            int index = target.indexOf(c);
            result[i] = source.charAt(index);
        }
        return new String(result);
    }

    public static double round(double value, int places) {
        if (places < 0) throw new IllegalArgumentException();
        BigDecimal bd = new BigDecimal(value);
        bd = bd.setScale(places, RoundingMode.HALF_UP);
        return bd.doubleValue();
    }

    public static byte[] Bytes2bytes(Byte[] Bytes) {
        byte[] bytes = new byte[Bytes.length];
        int x = 0;
        for (Byte b: Bytes) bytes[x++] = b.byteValue();
        return bytes;
    }

    public static Byte[] bytes2Bytes(byte[] bytes) {
        Byte[] Bytes = new Byte[bytes.length];
        int x = 0;
        for(byte b: bytes) Bytes[x++] = b;
        return Bytes;
    }

    public static byte[] bytesofbytes(byte[] bytes,int StartIndex, int length) {
        if (length<0) return null;
        byte[] ResultBytes = new byte[length];
        System.arraycopy(bytes, StartIndex, ResultBytes, 0, length);
        return ResultBytes;
    }

    public static int bytes2int(byte[] bytes, int size) {
        int result = 0;
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        switch (size) {
            case uint8_t:
                result = buffer.getChar();
                break;
            case uint16_t:
                result = buffer.getShort();
                break;
            case uint32_t:
                result = buffer.getInt();
                break;
        }
        return result;
    }

    public static byte[] int2bytes(int size, int value) {
        // TODO: this null return would break a lot of code
        //if (size != uint8_t && size != uint16_t && size != uint32_t) return null;
        byte[] thebytes = ByteBuffer.allocate(uint32_t).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array();
        if (size == uint8_t) {
            byte[] retVal = new byte[uint8_t];
            retVal[0] = thebytes[0];
            return retVal;
        }
        if (size == uint16_t) {
            byte[] retVal = new byte[uint16_t];
            retVal[0] = thebytes[0];
            retVal[1] = thebytes[1];
            return retVal;
        }
        else return thebytes;
    }

    public static byte[] bytesconcat(byte[] originalbytes, byte[] addedbytes) {
        byte[] retval = new byte[originalbytes.length + addedbytes.length];
        if (originalbytes.length > 0)
            System.arraycopy(originalbytes, 0, retval, 0, originalbytes.length);
        if (addedbytes.length > 0)
            System.arraycopy(addedbytes, 0, retval, originalbytes.length, addedbytes.length);
        return retval;
    }

    /**
     * Translate the given string into bytes and prepend it with length
     * @param s
     * @return
     */
    public static byte[] stringToByteStruct(String s) {
        byte[] lengthBytes = Utilities.int2bytes(uint16_t, s.length());
        return Utilities.bytesconcat(lengthBytes, s.getBytes());
    }

    public static int extractInt(byte[] bytes, int offset, int type) {
        return bytes2int(bytesofbytes(bytes, offset, type), type);
    }
    public static String extractString(byte[] bytes, int offset) {
        if (bytes.length < uint16_t) {
            return "";
        }
        int length = bytes2int(bytesofbytes(bytes, offset, uint16_t), uint16_t);
        offset += uint16_t;
        return bytes2string(bytesofbytes(bytes,offset,length));
    }

    public static String bytes2string(byte[] bytes) {
        try {
            return new String(bytes, "UTF-8");
        } catch(UnsupportedEncodingException e) {
            return "";
        }
    }
}
