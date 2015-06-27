/*
 * Copyright (c) 2013 TRUSTONIC LIMITED
 * All rights reserved
 *
 * The present software is the confidential and proprietary information of
 * TRUSTONIC LIMITED. You shall not disclose the present software and shall
 * use it only in accordance with the terms of the license agreement you
 * entered into with TRUSTONIC LIMITED. This software may be subject to
 * export or import laws in certain countries.
 */

package com.rivetz.stub;

import android.util.Log;

public class Constants {
    // Log tag.
    public static final String LOG_TAG = "RivetAndroid";
    // Show progress indicator (to disable if running on QEMU).
    public static final boolean PROGRESS_INDICATOR_ENABLED = true;
    // Service Provider ID for the Developer Account
    public static final String DEVELOPER_SPID = "029d785242baad9f3d7bedcfca29d5391b3c247a3d4eaf5c3a0a5edd9489d1fcad";
    // public static final String RIVETZ_SPID = "029755B26A5A1992B6C2CA1F732A0CBBDCE9D08CB6FC00CBEAC63F4078B5AA3950";
    public static final String RIVETZ_SPID = "029755b26a5a1992b6c2ca1f732a0cbbdce9d08cb6fc00cbeac63f4078b5aa3950";
    // the name of the file for writing and reading the TA code
    public static final String TAFILENAME = "ta.bin";

    // TODO: switch dependence to utilities
    public static final int uint8_t = Utilities.uint8_t;
    public static final int uint16_t = Utilities.uint16_t;
    public static final int uint32_t = Utilities.uint32_t;
    public static final int uint64_t = Utilities.uint64_t;
}

