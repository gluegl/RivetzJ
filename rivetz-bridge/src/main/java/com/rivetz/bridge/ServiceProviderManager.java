package com.rivetz.bridge;

import android.content.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.rivetz.lib.ServiceProviderRecord;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.InputStream;
import java.util.ArrayList;

/**
 * Helper class for loading service provider data
 *
 * ServiceProviderManager is a singleton. Once initialized with
 * Context it can then be used anywhere.
 *
 * Records are stored on disk in byte stream format
 */
public class ServiceProviderManager {
    private static final Logger log = LoggerFactory.getLogger(ServiceProviderManager.class);
    public int status; //TODO: normalize error handling for SPM
    // the array list is is used in an a display adapter in MainActivity
    public ArrayList<ServiceProviderRecord> list;
    private static ServiceProviderManager myself;

    private Context mContext;
    public enum ResultCode {
        SUCCESS,    // completed as expected
        FAIL        // generic failure
    }

    private ServiceProviderManager() {
    }

    public static ServiceProviderManager getInstance() {
        if (myself == null) {
            myself = new ServiceProviderManager();
        }
        return myself;
    }
    public void init(Context contextGiven) {
        if (mContext == null) {
            mContext = contextGiven;
        }
        if (list == null) {
            list = new ArrayList<ServiceProviderRecord>();
        }
    }

    public ResultCode loadLocal(String spid) {
        return(loadLocal(new ServiceProviderRecord(spid)));
    }

    public ResultCode loadLocal(ServiceProviderRecord record) {
        if (record == null || record.spid.isEmpty()) {
            return ResultCode.FAIL;
        }
        return loadFile(record, "sp." + record.spid);
    }

    public ResultCode saveLocal(ServiceProviderRecord record) {
        if (record == null) {
            return ResultCode.FAIL;
        } else if (!record.validate()) {
            return ResultCode.FAIL;
        }
        String filename = "sp." + record.spid;
        try {
            FileOutputStream outputStream = mContext.openFileOutput(filename, Context.MODE_PRIVATE);
            outputStream.write(record.serialize());
            outputStream.close();
        } catch (Exception e) {
            log.error("Failed to write SP Record to disk");
            e.printStackTrace();
        }
        loadAllLocal();
        return ResultCode.SUCCESS;
    }

    public ResultCode deleteLocal(ServiceProviderRecord record) {
        return(deleteLocal(record.spid));
    }
    public ResultCode deleteLocal(String spid) {
        String filename = "sp." + spid;

        try {
            mContext.deleteFile(filename);
        } catch(Exception e) {
            log.error("Failed to delete "+filename);
            return ResultCode.FAIL;
        }
        loadAllLocal();

        return ResultCode.SUCCESS;
    }

    public void loadAllLocal() {
        File dir = mContext.getFilesDir();

        FilenameFilter spFilter = new FilenameFilter() {
            public boolean accept(File file, String name) {
                return (name.matches("^sp\\.(.*)"));
            }
        };

        String[] fileList = dir.list(spFilter);

        list.clear();
        for (String fileName : fileList) {
            ServiceProviderRecord record = new ServiceProviderRecord();
            ResultCode result = loadFile(record,fileName);
            if (result == ResultCode.SUCCESS) {
                list.add(record);
            }
        }
    }

    private ResultCode loadFile(ServiceProviderRecord record, String filename) {
        byte[] data = {};
        try {
            InputStream inputStream = mContext.openFileInput(filename);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            if (inputStream != null) {

                byte[] buffer = new byte[4096];
                while(true) {
                    int n = inputStream.read(buffer);
                    if( n < 0 ) break;
                    baos.write(buffer, 0, n);
                }
                inputStream.close();
                data = baos.toByteArray();
            }
        } catch (Exception e) {
            log.warn("Failed to load "+filename);
            e.printStackTrace();
        }
        if (data.length == 0) {
            return ResultCode.FAIL;
        }
        record.Deserialize(data);
        return ResultCode.SUCCESS;
    }
    public boolean exists(String spid) {
        loadAllLocal();
        for (ServiceProviderRecord r : list) {
            if (r.spid.equals(spid)) {
                return true;
            }
        }
        return false;
    }
}
