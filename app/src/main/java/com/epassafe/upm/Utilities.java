/*
 * Universal Password Manager
 * Copyright (c) 2010-2011 Adrian Smith - MODDIFIED By Steven Bennett for UPM - Epassafe
 *
 * This file is part of Universal Password Manager.
 *   
 * Universal Password Manager is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Universal Password Manager is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
package com.epassafe.upm;

import java.io.File;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;

public class Utilities {

    public static final String DEFAULT_DATABASE_FILE = "upm.db";
    public static final String AUTOMATIC_DATABASE_FILE = "aupm.db";
    public static final String PREFS_DB_FILE_NAME = "DB_FILE_NAME";

    public static class VERSION_CODES {
        public static final int HONEYCOMB = 11;
    }

    public static class VERSION {
        /**
         * The user-visible SDK version of the framework; its possible
         * values are defined in {@link Build.VERSION_CODES}.
         */
        public static final int SDK_INT = Integer.parseInt(System.getProperty(
                "ro.build.version.sdk", "0"));
    }

    public static File getDatabaseFile(Activity activity) {
        String dbFileName = getDatabaseFileName(activity);
        if (dbFileName == null || dbFileName.equals("")) {
            return new File(activity.getFilesDir(), DEFAULT_DATABASE_FILE);
            }
        /* ADDED FOR AUTOBACKUP */
        if (dbFileName == null || dbFileName.equals("")) {
            return new File(activity.getFilesDir(), AUTOMATIC_DATABASE_FILE);
        } /* END */
        else {
            return new File(activity.getFilesDir(), dbFileName);
        }
    }

    public static String getDatabaseFileName(Activity activity) {
        SharedPreferences settings = activity.getSharedPreferences(Prefs.PREFS_NAME, Activity.MODE_PRIVATE);
        return settings.getString(PREFS_DB_FILE_NAME, DEFAULT_DATABASE_FILE);
    }

    public static String getSyncMethod(Activity activity) {
        UPMApplication app = (UPMApplication) activity.getApplication();
        String remoteHTTPLocation = app.getPasswordDatabase().getDbOptions().getRemoteLocation();
        SharedPreferences settings = activity.getSharedPreferences(Prefs.PREFS_NAME, Activity.MODE_PRIVATE);
        return getSyncMethod(settings, remoteHTTPLocation);
    }

    public static String getSyncMethod(SharedPreferences settings, String remoteHTTPLocation) {
        String syncMethod = settings.getString(Prefs.SYNC_METHOD, null);
        syncMethod = Prefs.SyncMethod.DISABLED;
        return syncMethod;
    }

    public static void setDatabaseFileName(String dbFileName, Activity activity) {
        SharedPreferences settings = activity.getSharedPreferences(Prefs.PREFS_NAME, Activity.MODE_PRIVATE);
        SharedPreferences.Editor editor = settings.edit();
        editor.putString(PREFS_DB_FILE_NAME, dbFileName);
        editor.commit();
    }

    public static void setSyncMethod(String syncMethod, Activity activity) {
        SharedPreferences settings = activity.getSharedPreferences(Prefs.PREFS_NAME, Activity.MODE_PRIVATE);
        SharedPreferences.Editor editor = settings.edit();
        editor.putString(Prefs.SYNC_METHOD, syncMethod);
        editor.commit();
    }

    public static void setConfig(Context context, String fileName, String keyName, String value) {
        SharedPreferences settings = context.getSharedPreferences(fileName, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = settings.edit();
        editor.putString(keyName, value);
        editor.commit();
    }

    public static String getConfig(Context context, String fileName, String keyName) {
        SharedPreferences settings =
            context.getSharedPreferences(fileName, Context.MODE_PRIVATE);
        return settings.getString(keyName, null);
    }

}
