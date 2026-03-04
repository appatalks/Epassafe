/*
 * Universal Password Manager
 * Copyright (c) 2010-2011 Adrian Smith - MODIFIED By Steven Bennett for UPM - Epassafe
 *
 * This file is part of Universal Password Manager.
 *   
 * Universal Password Manager is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at any later version).
 *
 * Universal Password Manager is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
package com.epassafe.upm;

import android.app.Activity;
import android.app.Application;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.Environment;
import android.provider.MediaStore;
import android.util.Log;
import android.widget.Toast;

import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsControllerCompat;

import com.epassafe.upm.database.PasswordDatabase;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.FileChannel;

/**
 * This class replaces the regular Application class in the application and
 * allows us to store data at the application level.
 */
public class UPMApplication extends Application {

    private PasswordDatabase passwordDatabase;

    @Override
    public void onCreate() {
        super.onCreate();
        // Enable edge-to-edge display for backward compatibility with Android versions before 15
        // This is needed per Google Play Store recommendation for apps targeting SDK 35
    }

    /**
     * Enables edge-to-edge display for an activity
     * This should be called from the onCreate method of each activity
     * @param activity The activity to enable edge-to-edge for
     */
    public void enableEdgeToEdge(Activity activity) {
        if (activity != null && activity.getWindow() != null) {
            // This is the recommended way to enable edge-to-edge display
            WindowCompat.setDecorFitsSystemWindows(activity.getWindow(), false);

            // Make system bars (status and navigation) visible over your content
            WindowInsetsControllerCompat controller = new WindowInsetsControllerCompat(activity.getWindow(), activity.getWindow().getDecorView());
            controller.setAppearanceLightStatusBars(true); // Adjust based on your app's theme
        }
    }

    public void setPasswordDatabase(PasswordDatabase passwordDatabase) {
        this.passwordDatabase = passwordDatabase;
    }

    public PasswordDatabase getPasswordDatabase() {
        return passwordDatabase;
    }

    protected boolean copyFile(File source, File dest, Activity activity) {
        boolean successful = false;

        FileChannel sourceChannel = null;
        FileChannel destinationChannel = null;
        FileInputStream is = null;
        FileOutputStream os = null;
        try {
            is = new FileInputStream(source);
            sourceChannel = is.getChannel();

            File destFile = null;
            if (dest.isDirectory()) {
                destFile = new File(dest, source.getName());
            } else {
                destFile = dest;
            }

            os = new FileOutputStream(destFile);
            destinationChannel = os.getChannel();
            destinationChannel.transferFrom(sourceChannel, 0, sourceChannel.size());

            successful=true;
        } catch (IOException e) {
            Log.e(activity.getClass().getName(), getString(R.string.file_problem), e);
            Toast.makeText(activity, R.string.file_problem, Toast.LENGTH_LONG).show();
        } finally {
            try {
                if (sourceChannel != null) {
                    sourceChannel.close();
                }
                if (is != null) {
                    is.close();
                }
                if (destinationChannel != null) {
                    destinationChannel.close();
                }
                if (os != null) {
                    os.close();
                }
            } catch (IOException e) {
                Log.e(activity.getClass().getName(), getString(R.string.file_problem), e);
                Toast.makeText(activity, R.string.file_problem, Toast.LENGTH_LONG).show();
            }
        }

        return successful;
    }

    protected void restoreDatabase(Activity activity) {

        deleteDatabase(activity);
        File fileOnSDCard = new File(getExternalFilesDir("database"), Utilities.DEFAULT_DATABASE_FILE);
        File databaseFile = Utilities.getDatabaseFile(activity);
        ((UPMApplication) activity.getApplication()).copyFile(fileOnSDCard, databaseFile, activity);
    }

    protected void deleteDatabase(Activity activity) {
        Utilities.getDatabaseFile(activity).delete();
        Utilities.setDatabaseFileName(null, activity);
    }

    /**
     * Backup the database to the public Downloads folder using MediaStore.
     * No special permissions needed on Android 10+.
     */
    protected boolean backupToDownloads(Activity activity) {
        File databaseFile = Utilities.getDatabaseFile(activity);
        if (!databaseFile.exists()) {
            Toast.makeText(activity, R.string.file_problem, Toast.LENGTH_LONG).show();
            return false;
        }

        ContentResolver resolver = activity.getContentResolver();
        String fileName = Utilities.DEFAULT_DATABASE_FILE;

        // Delete existing backup in Downloads if present
        Uri existingUri = findDownloadsFile(resolver, fileName);
        if (existingUri != null) {
            resolver.delete(existingUri, null, null);
        }

        ContentValues values = new ContentValues();
        values.put(MediaStore.Downloads.DISPLAY_NAME, fileName);
        values.put(MediaStore.Downloads.MIME_TYPE, "application/octet-stream");
        values.put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS);

        Uri uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values);
        if (uri == null) {
            Toast.makeText(activity, R.string.backup_downloads_failed, Toast.LENGTH_LONG).show();
            return false;
        }

        try (FileInputStream fis = new FileInputStream(databaseFile);
             OutputStream os = resolver.openOutputStream(uri)) {
            if (os == null) {
                Toast.makeText(activity, R.string.backup_downloads_failed, Toast.LENGTH_LONG).show();
                return false;
            }
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                os.write(buffer, 0, bytesRead);
            }
            return true;
        } catch (IOException e) {
            Log.e("UPMApplication", "Error backing up to Downloads", e);
            Toast.makeText(activity, R.string.backup_downloads_failed, Toast.LENGTH_LONG).show();
            return false;
        }
    }

    /**
     * Restore database from a URI (picked via SAF file picker).
     */
    protected boolean restoreFromUri(Activity activity, Uri sourceUri) {
        if (sourceUri == null) {
            return false;
        }

        deleteDatabase(activity);
        File databaseFile = Utilities.getDatabaseFile(activity);

        try (InputStream is = activity.getContentResolver().openInputStream(sourceUri);
             FileOutputStream fos = new FileOutputStream(databaseFile)) {
            if (is == null) {
                Toast.makeText(activity, R.string.restore_downloads_failed, Toast.LENGTH_LONG).show();
                return false;
            }
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = is.read(buffer)) != -1) {
                fos.write(buffer, 0, bytesRead);
            }
            return true;
        } catch (IOException e) {
            Log.e("UPMApplication", "Error restoring from URI", e);
            Toast.makeText(activity, R.string.restore_downloads_failed, Toast.LENGTH_LONG).show();
            return false;
        }
    }

    /**
     * Check if a backup file already exists in the Downloads folder.
     */
    protected boolean downloadsBackupExists(Activity activity) {
        return findDownloadsFile(activity.getContentResolver(), Utilities.DEFAULT_DATABASE_FILE) != null;
    }

    /**
     * Find a file in the Downloads folder by display name.
     */
    private Uri findDownloadsFile(ContentResolver resolver, String displayName) {
        Uri collection = MediaStore.Downloads.EXTERNAL_CONTENT_URI;
        String[] projection = {MediaStore.Downloads._ID};
        String selection = MediaStore.Downloads.DISPLAY_NAME + "=?";
        String[] selectionArgs = {displayName};

        try (Cursor cursor = resolver.query(collection, projection, selection, selectionArgs, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                long id = cursor.getLong(cursor.getColumnIndexOrThrow(MediaStore.Downloads._ID));
                return Uri.withAppendedPath(collection, String.valueOf(id));
            }
        }
        return null;
    }

}
