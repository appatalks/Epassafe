/*
 * Universal Password Manager
 \* Copyright (c) 2010-2011 Adrian Smith - MODDIFIED By Steven Bennett for UPM - Epassafe
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Universal Password Manager; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
package com.epassafe.upm;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;

import android.app.Activity;
import android.app.ProgressDialog;
import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import com.epassafe.upm.crypto.InvalidPasswordException;
import com.epassafe.upm.database.PasswordDatabase;
import com.epassafe.upm.database.ProblemReadingDatabaseFile;

public class ChangeMasterPassword extends Activity {

    private EditText existingPasswordEditText;
    private EditText newPassword1EditText;
    private EditText newPassword2EditText;
    private CheckBox modernEncryptionCheckbox;
    private CheckBox useChaCha20Checkbox;
    private LinearLayout encryptionOptionsLayout;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.change_master_password);

        existingPasswordEditText = (EditText) findViewById(R.id.existing_master_password);
        newPassword1EditText = (EditText) findViewById(R.id.new_master_password1);
        newPassword2EditText = (EditText) findViewById(R.id.new_master_password2);

        // Add new UI elements for encryption options
        modernEncryptionCheckbox = (CheckBox) findViewById(R.id.modern_encryption_checkbox);
        useChaCha20Checkbox = (CheckBox) findViewById(R.id.use_chacha20_checkbox);
        encryptionOptionsLayout = (LinearLayout) findViewById(R.id.encryption_options_layout);

        // Set initial state based on current encryption
        PasswordDatabase db = ((UPMApplication) getApplication()).getPasswordDatabase();
        if (db != null) {
            boolean isUsingModern = db.isUsingModernEncryption();
            modernEncryptionCheckbox.setChecked(isUsingModern);

            // Show/hide ChaCha20 option based on modern encryption being enabled
            useChaCha20Checkbox.setEnabled(isUsingModern);

            // Add explanation text
            TextView encryptionInfo = (TextView) findViewById(R.id.encryption_info);
            if (encryptionInfo != null) {
                encryptionInfo.setText(getString(R.string.current_encryption) + " " + db.getEncryptionAlgorithm());
            }

            // Set listener for modern encryption checkbox
            modernEncryptionCheckbox.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
                @Override
                public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                    useChaCha20Checkbox.setEnabled(isChecked);
                }
            });
        }
        
        Button okButton = (Button) findViewById(R.id.change_master_password_button);
        okButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (validateInput()) {
                    new ChangeMasterPasswordTask().execute();
                }
            }
        });
    }

    private boolean validateInput() {
        boolean valid = true;

        // Check existing password
        if (existingPasswordEditText.getText().toString().length() == 0) {
            UIUtilities.showToast(this, R.string.invalid_password, false);
            existingPasswordEditText.requestFocus();
            return false;
        }

        // Check passwords match
        String newPassword1 = newPassword1EditText.getText().toString();
        String newPassword2 = newPassword2EditText.getText().toString();
        if (!newPassword1.equals(newPassword2)) {
            UIUtilities.showToast(this, R.string.new_passwords_dont_match, false);
            newPassword1EditText.requestFocus();
            valid = false;
        }

        // Check password length (minimum 8 characters)
        if (newPassword1.length() < 8) {
            UIUtilities.showToast(this,
                    String.format(getString(R.string.password_too_short), 8),
                    false);
            newPassword1EditText.requestFocus();
            valid = false;
        }

        return valid;
    }

    private class ChangeMasterPasswordTask extends AsyncTask<Void, Void, Integer> {

        private static final int RESULT_OK = 0;
        private static final int RESULT_INCORRECT_EXISTING_PASSWORD = 1;
        private static final int RESULT_ENCRYPTION_FAILED = 2;

        private String errorMessage;
        private ProgressDialog progressDialog;

        @Override
        protected void onPreExecute() {
            progressDialog = ProgressDialog.show(ChangeMasterPassword.this, "",
                    getString(R.string.changing_master_password));
        }

        @Override
        protected Integer doInBackground(Void... params) {
            PasswordDatabase database = ((UPMApplication) getApplication()).getPasswordDatabase();

            try {
                char[] existingPassword = existingPasswordEditText.getText().toString().toCharArray();
                File dbFile = database.getDatabaseFile();

                // Verify the existing password on background thread
                PasswordDatabase testDB = new PasswordDatabase(dbFile, existingPassword);

                // If we got here then the password was correct
                char[] newPassword = newPassword1EditText.getText().toString().toCharArray();

                // Check if we should upgrade to modern encryption
                boolean useModernEncryption = modernEncryptionCheckbox.isChecked();
                boolean useChaCha20 = useChaCha20Checkbox.isChecked();

                try {
                    // First change the password
                    database.changePassword(newPassword);

                    // Then upgrade encryption if requested
                    if (useModernEncryption && !database.isUsingModernEncryption()) {
                        try {
                            database.upgradeToModernEncryption(newPassword, useChaCha20);
                        } catch (Exception e) {
                            Log.e("ChangeMasterPassword", "Error upgrading encryption", e);
                            errorMessage = "Error upgrading encryption: " + e.getMessage();
                            return RESULT_ENCRYPTION_FAILED;
                        }
                    }

                    // Save the database but don't wait for UI callbacks
                    try {
                        database.save();
                        return RESULT_OK;
                    } catch (Exception e) {
                        Log.e("ChangeMasterPassword", "Error saving database", e);
                        errorMessage = "Error saving database: " + e.getMessage();
                        return RESULT_ENCRYPTION_FAILED;
                    }
                } catch (GeneralSecurityException e) {
                    Log.e("ChangeMasterPassword", "Security error", e);
                    errorMessage = e.getMessage();
                    return RESULT_ENCRYPTION_FAILED;
                }
            } catch (InvalidPasswordException e) {
                return RESULT_INCORRECT_EXISTING_PASSWORD;
            } catch (Exception e) {
                Log.e("ChangeMasterPassword", "Unexpected error", e);
                errorMessage = e.getMessage();
                return RESULT_ENCRYPTION_FAILED;
            }
        }

        @Override
        protected void onPostExecute(Integer result) {
            progressDialog.dismiss();
            switch (result) {
                case RESULT_OK:
                    UIUtilities.showToast(ChangeMasterPassword.this,
                            R.string.master_password_changed, true);
                    finish();
                    break;
                case RESULT_INCORRECT_EXISTING_PASSWORD:
                    UIUtilities.showToast(ChangeMasterPassword.this,
                            R.string.incorrect_password, false);
                    existingPasswordEditText.requestFocus();
                    break;
                case RESULT_ENCRYPTION_FAILED:
                    String message = String.format(
                            getString(R.string.master_password_change_failed),
                            errorMessage);
                    UIUtilities.showToast(ChangeMasterPassword.this, message, true);
                    break;
            }
        }
    }
}
