package com.budgettracker.sms;

import android.Manifest;
import android.database.Cursor;
import android.net.Uri;
import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;
import com.getcapacitor.PermissionState;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;
import com.getcapacitor.annotation.Permission;
import com.getcapacitor.annotation.PermissionCallback;

@CapacitorPlugin(
    name = "Sms",
    permissions = {
        @Permission(strings = { Manifest.permission.READ_SMS }, alias = "readSms")
    }
)
public class SmsPlugin extends Plugin {

    @PluginMethod
    public void getMessages(PluginCall call) {
        if (getPermissionState("readSms") != PermissionState.GRANTED) {
            requestPermissionForAlias("readSms", call, "smsPermissionCallback");
            return;
        }
        readAndReturnMessages(call);
    }

    @PermissionCallback
    private void smsPermissionCallback(PluginCall call) {
        if (getPermissionState("readSms") == PermissionState.GRANTED) {
            readAndReturnMessages(call);
        } else {
            call.reject("SMS permission denied");
        }
    }

    private void readAndReturnMessages(PluginCall call) {
        JSArray messages = new JSArray();
        Uri uri = Uri.parse("content://sms/inbox");
        String[] projection = { "address", "body", "date" };
        long sixMonthsAgo = System.currentTimeMillis() - (180L * 24L * 60L * 60L * 1000L);
        String selection = "date > ?";
        String[] selectionArgs = { String.valueOf(sixMonthsAgo) };

        try (Cursor cursor = getContext().getContentResolver().query(
                uri, projection, selection, selectionArgs, "date DESC")) {
            if (cursor != null) {
                while (cursor.moveToNext()) {
                    JSObject msg = new JSObject();
                    msg.put("address", cursor.getString(0));
                    msg.put("body",    cursor.getString(1));
                    msg.put("date",    cursor.getLong(2));
                    messages.put(msg);
                }
            }
        } catch (Exception e) {
            call.reject("Error reading SMS: " + e.getMessage());
            return;
        }

        JSObject result = new JSObject();
        result.put("messages", messages);
        call.resolve(result);
    }
}
