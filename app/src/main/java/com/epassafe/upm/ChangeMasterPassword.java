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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 */
package com.epassafe.upm;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.DialogInterface;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Environment;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import com.epassafe.upm.crypto.DatabaseExporter;
import com.epassafe.upm.crypto.InvalidPasswordException;
import com.epassafe.upm.database.PasswordDatabase;
import com.epassafe.upm.database.ProblemReadingDatabaseFile;

public class ChangeMasterPassword extends Activity {

    private EditText existingPasswordEditText;
    private EditText newPassword1EditText;
    private EditText newPassword2EditText;
    private CheckBox modernEncryptionCheckbox;
    private CheckBox useChaCha20Checkbox;
    private CheckBox exportCsvCheckbox;
    private LinearLayout encryptionOptionsLayout;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.change_master_password);

        existingPasswordEditText = findViewById(R.id.existing_master_password);
        newPassword1EditText = findViewById(R.id.new_master_password1);
        newPassword2EditText = findViewById(R.id.new_master_password2);

        // Add UI elements for encryption options
        modernEncryptionCheckbox = findViewById(R.id.modern_encryption_checkbox);
        useChaCha20Checkbox = findViewById(R.id.use_chacha20_checkbox);
        exportCsvCheckbox = findViewById(R.id.export_csv_checkbox);
        encryptionOptionsLayout = findViewById(R.id.encryption_options_layout);

        // Set initial state based on current encryption
        final PasswordDatabase db = ((UPMApplication) getApplication()).getPasswordDatabase();
        if (db != null) {
            boolean isUsingModern = db.isUsingModernEncryption();
            modernEncryptionCheckbox.setChecked(isUsingModern);

            // Check if ChaCha20 is being used and set checkbox accordingly
            if (isUsingModern) {
                String algorithm = db.getEncryptionAlgorithm();
                boolean isUsingChaCha = algorithm.contains("ChaCha20");
                useChaCha20Checkbox.setChecked(isUsingChaCha);
            }

            // Show/hide ChaCha20 option based on modern encryption being enabled
            useChaCha20Checkbox.setEnabled(isUsingModern);

            // Add explanation text
            TextView encryptionInfo = findViewById(R.id.encryption_info);
            if (encryptionInfo != null) {
                encryptionInfo.setText(getString(R.string.current_encryption) + " " + db.getEncryptionAlgorithm());
            }

            // Set listeners for encryption selection
            modernEncryptionCheckbox.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
                @Override
                public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                    useChaCha20Checkbox.setEnabled(isChecked);

                    // Show warning when trying to disable modern encryption
                    if (!isChecked && db.isUsingModernEncryption()) {
                        new AlertDialog.Builder(ChangeMasterPassword.this)
                            .setTitle(R.string.encryption_downgrade_warning_title)
                            .setMessage(R.string.encryption_downgrade_warning)
                            .setPositiveButton(R.string.yes, new DialogInterface.OnClickListener() {
                                @Override
                                public void onClick(DialogInterface dialog, int which) {
                                    // User confirmed disabling modern encryption
                                }
                            })
                            .setNegativeButton(R.string.no, new DialogInterface.OnClickListener() {
                                @Override
                                public void onClick(DialogInterface dialog, int which) {
                                    // User canceled, revert the checkbox
                                    modernEncryptionCheckbox.setChecked(true);
                                }
                            })
                            .setIcon(android.R.drawable.ic_dialog_alert)
                            .show();
                    }
                }
            });

            // Add warning dialog for CSV export checkbox
            exportCsvCheckbox.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
                @Override
                public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                    if (isChecked) {
                        new AlertDialog.Builder(ChangeMasterPassword.this)
                            .setTitle("Security Warning")
                            .setMessage("This will export ALL your passwords to an unencrypted CSV file. " +
                                        "Anyone with access to this file will be able to see your passwords. " +
                                        "Are you sure you want to continue?")
                            .setPositiveButton("Yes", new DialogInterface.OnClickListener() {
                                @Override
                                public void onClick(DialogInterface dialog, int which) {
                                    // Keep checkbox checked
                                }
                            })
                            .setNegativeButton("No", new DialogInterface.OnClickListener() {
                                @Override
                                public void onClick(DialogInterface dialog, int which) {
                                    // Uncheck the box
                                    exportCsvCheckbox.setChecked(false);
                                }
                            })
                            .setIcon(android.R.drawable.ic_dialog_alert)
                            .show();
                    }
                }
            });
        }

        Button okButton = findViewById(R.id.change_master_password_button);
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

        // Check if doing CSV export only (no password change)
        if (exportCsvCheckbox.isChecked() &&
            newPassword1EditText.getText().toString().length() == 0 &&
            newPassword2EditText.getText().toString().length() == 0) {
            // This is valid - we're just exporting to CSV without changing password
            return true;
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
        if (newPassword1.length() > 0 && newPassword1.length() < 8) {
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
        private static final int RESULT_CSV_ONLY = 3;
        private static final int RESULT_CSV_FAILED = 4;

        private String errorMessage;
        private String csvFilePath;
        private ProgressDialog progressDialog;

        @Override
        protected void onPreExecute() {
            // Show appropriate message based on whether we're exporting to CSV or changing password
            if (exportCsvCheckbox.isChecked() &&
                newPassword1EditText.getText().toString().length() == 0 &&
                newPassword2EditText.getText().toString().length() == 0) {
                // Only exporting to CSV
                progressDialog = ProgressDialog.show(ChangeMasterPassword.this, "",
                        getString(R.string.exporting_csv));
            } else {
                // Changing password (possibly with CSV export)
                progressDialog = ProgressDialog.show(ChangeMasterPassword.this, "",
                        getString(R.string.changing_master_password));
            }
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

                // Check if we need to export to CSV
                if (exportCsvCheckbox.isChecked()) {
                    // Create a file in the Downloads directory with timestamp
                    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd_HHmmss", Locale.US);
                    String timestamp = sdf.format(new Date());
                    String filename = "epassafe_export_" + timestamp + ".csv";

                    File downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
                    File csvFile = new File(downloadsDir, filename);

                    boolean exportSuccess = DatabaseExporter.exportToCSV(database, csvFile);
                    if (exportSuccess) {
                        csvFilePath = csvFile.getAbsolutePath();
                        Log.i("ChangeMasterPassword", "Successfully exported database to " + csvFilePath);
                    } else {
                        Log.e("ChangeMasterPassword", "Failed to export database to CSV");
                        return RESULT_CSV_FAILED;
                    }

                    // If we're only doing CSV export (no password change)
                    String newPassword1 = newPassword1EditText.getText().toString();
                    if (newPassword1.length() == 0) {
                        return RESULT_CSV_ONLY;
                    }
                }

                // If we need to change the password
                char[] newPassword = newPassword1EditText.getText().toString().toCharArray();

                // Check which encryption type is selected
                boolean useModernEncryption = modernEncryptionCheckbox.isChecked();
                boolean useChaCha20 = useChaCha20Checkbox.isChecked();

                boolean isCurrentlyModern = database.isUsingModernEncryption();
                boolean isCurrentlyChaCha = database.getEncryptionAlgorithm().contains("ChaCha20");

                try {
                    // First change the password
                    database.changePassword(newPassword);

                    // Handle encryption changes based on selection
                    if (useModernEncryption) {
                        if (!isCurrentlyModern) {
                            // Upgrade to modern from legacy
                            database.upgradeToModernEncryption(newPassword, useChaCha20);
                            Log.i("ChangeMasterPassword", "Upgraded to modern encryption with " +
                                  (useChaCha20 ? "ChaCha20-Poly1305" : "AES-GCM"));
                        } else if (isCurrentlyChaCha != useChaCha20) {
                            // Switch between AES-GCM and ChaCha20-Poly1305
                            database.switchModernAlgorithm(useChaCha20);
                            Log.i("ChangeMasterPassword", "Switched to " +
                                  (useChaCha20 ? "ChaCha20-Poly1305" : "AES-GCM"));
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
                    if (csvFilePath != null) {
                        String message = "Master password changed and database exported to: " + csvFilePath;
                        UIUtilities.showToast(ChangeMasterPassword.this, message, true);
                    } else {
                        UIUtilities.showToast(ChangeMasterPassword.this,
                            R.string.master_password_changed, true);
                    }
                    finish();
                    break;
                case RESULT_CSV_ONLY:
                    UIUtilities.showToast(ChangeMasterPassword.this,
                            "Database exported to: " + csvFilePath, true);
                    finish();
                    break;
                case RESULT_CSV_FAILED:
                    UIUtilities.showToast(ChangeMasterPassword.this,
                            "Failed to export database to CSV file", true);
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

