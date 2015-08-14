package com.rivetz.bridge;

import android.app.Service;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.util.Log;
import android.widget.Toast;

import com.rivetz.adapter.IRivetzAPI;

import java.util.concurrent.Callable;

class Binder {
    private ServiceConnection apiConnection;
    public IRivetzAPI api;
    private Context context;

    protected Binder(Context contextGiven, final Callable done) {
        context = contextGiven;
        if (api != null) {
            try {
                done.call();
            } catch(Exception e) {
                //
            }
            return;
        }
        apiConnection = new ServiceConnection() {
            @Override
            public void onServiceDisconnected(ComponentName name) {
                api = null;
                Toast.makeText(context, "Rivet Disconnected",Toast.LENGTH_SHORT).show();
                Log.d("IRemote", "Binding - Rivet disconnected");
            }

            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                api = IRivetzAPI.Stub.asInterface((IBinder) service);
                Toast.makeText(context,"Rivet Connected", Toast.LENGTH_SHORT).show();
                Log.d("IRemote", "Binding - Rivet connected");
                try {
                    done.call();
                } catch(Exception e) {
                    //
                }
            }
        };
        if (api == null) {
            Intent it = new Intent("com.rivetz.adapter.RivetzAPI");
            it.setPackage("com.rivetz.adapter");
            context.startService(it);
            context.bindService(it, apiConnection, Service.BIND_AUTO_CREATE);
        }
    }
    protected void close() {
        context.unbindService(apiConnection);
    }
    protected boolean isInitialized() {return api != null;}
}
