/*
 * Universal Password Manager
 * Copyright (c) 2010-2011 Adrian Smith
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
 *
 * You should have received a copy of the GNU General Public License
 * along with Universal Password Manager; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
package com.epassafe.upm;

import java.util.ArrayList;

import android.content.SharedPreferences;
import android.content.res.Resources;
import android.os.Bundle;
import android.preference.EditTextPreference;
import android.preference.ListPreference;
import android.preference.Preference;
import android.preference.Preference.OnPreferenceChangeListener;
import android.preference.PreferenceActivity;
import android.preference.PreferenceCategory;
import android.view.KeyEvent;

import com.epassafe.upm.database.PasswordDatabase;

public class Prefs extends PreferenceActivity implements OnPreferenceChangeListener {

    // Name of the preferences file
    public static final String PREFS_NAME = "UPMPrefs";

    // Configuration setting constants
    public static final String SYNC_METHOD = "sync.method";

    public static interface SyncMethod {
        public static final String DISABLED = "disabled";
        public static final String HTTP = "http";
    }

    // Reference to the various preference objects
    private ListPreference syncMethodPreference;
    private ListPreference sharedURLAuthPref;
    private EditTextPreference sharedURLPref;

    private PasswordDatabase db;
    private String originalSyncMethod;
    private boolean saveRequired;

    private String[] syncMethodValues = {
            SyncMethod.DISABLED
    };
    private String[] syncMethodHuman;

    @SuppressWarnings({ "deprecation" })
	@Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        saveRequired = false;

        // Create the menu items
        addPreferencesFromResource(R.xml.settings);

        // Load the preferences
        SharedPreferences settings = getSharedPreferences(PREFS_NAME, 0);

        // Get a handle to the preference items
        sharedURLAuthPref = (ListPreference) findPreference("shared_url_auth");
        sharedURLPref = (EditTextPreference) findPreference("shared_url");
        sharedURLAuthPref.setOnPreferenceChangeListener(this);
        sharedURLPref.setOnPreferenceChangeListener(this);

        // Populate the preferences
        db = ((UPMApplication) getApplication()).getPasswordDatabase();
        String sharedURL = db.getDbOptions().getRemoteLocation();
        if (sharedURL.equals("")) {
            sharedURL = null;
        }
        sharedURLPref.setText(sharedURL);

        ArrayList<String> accountNamesAL = db.getAccountNames();
        String[] accountNames = new String[accountNamesAL.size() + 1];
        accountNames[0] = "";
        System.arraycopy(accountNamesAL.toArray(), 0, accountNames, 1, accountNamesAL.size());
        sharedURLAuthPref.setEntryValues(accountNames);
        sharedURLAuthPref.setEntries(accountNames);
        sharedURLAuthPref.setValue(db.getDbOptions().getAuthDBEntry());

        // Some preferences are stored using Android's SharedPreferences

        Resources res = getResources();
        syncMethodHuman= res.getStringArray(R.array.sync_methods_human);

        syncMethodPreference = (ListPreference) findPreference("sync_method");
        syncMethodPreference.setEntryValues(syncMethodValues);

        // Figure out what the sync method really is
        originalSyncMethod = Utilities.getSyncMethod(settings, sharedURL);

        // Populate the syncMethodPreference with what we've determined from
        // the stored preferences
        syncMethodPreference.setValue(originalSyncMethod);

        // Initialize the on-screen text based on the sync method
        initialiseFields(originalSyncMethod);

        syncMethodPreference.setOnPreferenceChangeListener(new OnPreferenceChangeListener() {
            @Override
            public boolean onPreferenceChange(Preference preference, Object newValue) {
                initialiseFields((String) newValue);

                if (!newValue.equals(originalSyncMethod) &&
                        (newValue.equals(SyncMethod.HTTP) || originalSyncMethod.equals(SyncMethod.HTTP))) {
                    saveRequired = true;
                }

                return true;
            }
        });
    }

    private void initialiseFields(String syncMethod) {
        // Set the SyncMethod summary to the value selected in the List
        for (int i=0; i<syncMethodValues.length; i++) {
            if (syncMethod.equals(syncMethodValues[i])) {
                syncMethodPreference.setSummary(syncMethodHuman[i]);
                break;
            }
        }
        }

    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (keyCode == KeyEvent.KEYCODE_BACK) {
            if (saveRequired) {
                new SaveDatabaseAsyncTask(this, new Callback() {
                    @Override
                    public void execute() {
                        Prefs.this.finish();
                    }
                }).execute(db);
                return true;
            }
        }
        return super.onKeyDown(keyCode, event);
    } 

    @Override
    public boolean onPreferenceChange(Preference preference, Object newValue) {
        if (preference == sharedURLAuthPref) {
            if (!sharedURLAuthPref.getValue().equals(newValue)) {
                saveRequired = true;
            }
        } else if (preference == sharedURLPref) {
            if (sharedURLPref.getText() == null && newValue != null ||
                    !sharedURLPref.getText().equals(newValue)) {
                saveRequired = true;
            }
        }

        return true;
    }

    @Override
    protected void onStop(){
        super.onStop();

       // We need an Editor object to make preference changes.
       // All objects are from android.context.Context
       SharedPreferences settings = getSharedPreferences(PREFS_NAME, 0);
       SharedPreferences.Editor editor = settings.edit();
       editor.putString(SYNC_METHOD, syncMethodPreference.getValue());

       // Commit the edits!
       editor.commit();
     }

}
