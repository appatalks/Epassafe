/*
 * Universal Password Manager
 * Copyright (c) 2010-2011 Adrian Smith - MODIFIED By Steven Bennett for UPM - Epassafe
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
import java.util.Arrays;
import java.util.Date;
import java.util.Locale;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.PendingIntent;
import android.app.ProgressDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
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
import android.widget.ProgressBar;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import com.epassafe.upm.crypto.DatabaseExporter;
import com.epassafe.upm.crypto.InvalidPasswordException;
import com.epassafe.upm.crypto.YubiKeyManager;
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

    // YubiKey enrollment
    private CheckBox yubiKeyEnableCheckbox;
    private Button yubiKeyEnrollButton;
    private TextView yubiKeyEnrollmentStatus;
    private TextView yubiKeyNfcPrompt;
    private ProgressBar yubiKeyEnrollProgress;
    private RadioGroup yubiKeyModeGroup;
    private NfcAdapter nfcAdapter;
    private boolean waitingForYubiKeyEnroll = false;
    private boolean waitingForYubiKeyRemove = false;
    private boolean yubiKeyCurrentlyEnrolled = false;
    private YubiKeyManager.UnlockMode selectedYubiKeyMode = YubiKeyManager.UnlockMode.PASSWORD_REQUIRED;

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

        // YubiKey enrollment setup
        yubiKeyEnableCheckbox = findViewById(R.id.yubikey_enable_checkbox);
        yubiKeyEnrollButton = findViewById(R.id.yubikey_enroll_button);
        yubiKeyEnrollmentStatus = findViewById(R.id.yubikey_enrollment_status);
        yubiKeyNfcPrompt = findViewById(R.id.yubikey_nfc_prompt);
        yubiKeyEnrollProgress = findViewById(R.id.yubikey_enroll_progress);
        yubiKeyModeGroup = findViewById(R.id.yubikey_mode_group);

        nfcAdapter = NfcAdapter.getDefaultAdapter(this);

        // Set up mode radio group listener
        if (yubiKeyModeGroup != null) {
            yubiKeyModeGroup.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
                @Override
                public void onCheckedChanged(RadioGroup group, int checkedId) {
                    if (checkedId == R.id.yubikey_mode_password_required) {
                        selectedYubiKeyMode = YubiKeyManager.UnlockMode.PASSWORD_REQUIRED;
                    } else if (checkedId == R.id.yubikey_mode_passwordless) {
                        selectedYubiKeyMode = YubiKeyManager.UnlockMode.PASSWORDLESS;
                    } else if (checkedId == R.id.yubikey_mode_optional) {
                        selectedYubiKeyMode = YubiKeyManager.UnlockMode.PASSWORD_OR_YUBIKEY;
                    }
                }
            });
        }

        if (db != null) {
            File dbFile = db.getDatabaseFile();
            yubiKeyCurrentlyEnrolled = YubiKeyManager.isEnrolled(dbFile);

            if (yubiKeyCurrentlyEnrolled) {
                yubiKeyEnrollmentStatus.setText(R.string.yubikey_enrolled);
                yubiKeyEnableCheckbox.setChecked(true);
                yubiKeyEnrollButton.setVisibility(View.VISIBLE);
                yubiKeyEnrollButton.setText(R.string.yubikey_remove_button);
                // Show current mode
                selectedYubiKeyMode = YubiKeyManager.loadMode(dbFile);
                if (yubiKeyModeGroup != null) {
                    yubiKeyModeGroup.setVisibility(View.VISIBLE);
                    switch (selectedYubiKeyMode) {
                        case PASSWORDLESS:
                            yubiKeyModeGroup.check(R.id.yubikey_mode_passwordless); break;
                        case PASSWORD_OR_YUBIKEY:
                            yubiKeyModeGroup.check(R.id.yubikey_mode_optional); break;
                        default:
                            yubiKeyModeGroup.check(R.id.yubikey_mode_password_required); break;
                    }
                    // Disable radio buttons when already enrolled (need to remove & re-enroll to change)
                    for (int i = 0; i < yubiKeyModeGroup.getChildCount(); i++)
                        yubiKeyModeGroup.getChildAt(i).setEnabled(false);
                }
            } else {
                yubiKeyEnrollmentStatus.setText(R.string.yubikey_not_enrolled);
                yubiKeyEnableCheckbox.setChecked(false);
            }

            yubiKeyEnableCheckbox.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
                @Override
                public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                    if (isChecked && !yubiKeyCurrentlyEnrolled) {
                        yubiKeyEnrollButton.setVisibility(View.VISIBLE);
                        yubiKeyEnrollButton.setText(R.string.yubikey_enroll_button);
                        if (yubiKeyModeGroup != null) {
                            yubiKeyModeGroup.setVisibility(View.VISIBLE);
                            for (int i = 0; i < yubiKeyModeGroup.getChildCount(); i++)
                                yubiKeyModeGroup.getChildAt(i).setEnabled(true);
                            yubiKeyModeGroup.check(R.id.yubikey_mode_password_required);
                        }
                    } else if (!isChecked && yubiKeyCurrentlyEnrolled) {
                        yubiKeyEnrollButton.setVisibility(View.VISIBLE);
                        yubiKeyEnrollButton.setText(R.string.yubikey_remove_button);
                        if (yubiKeyModeGroup != null) yubiKeyModeGroup.setVisibility(View.GONE);
                    } else {
                        yubiKeyEnrollButton.setVisibility(View.GONE);
                        yubiKeyNfcPrompt.setVisibility(View.GONE);
                        if (yubiKeyModeGroup != null) yubiKeyModeGroup.setVisibility(View.GONE);
                    }
                }
            });

            yubiKeyEnrollButton.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    // Verify password is entered
                    if (existingPasswordEditText.getText().toString().isEmpty()) {
                        UIUtilities.showToast(ChangeMasterPassword.this, R.string.invalid_password, false);
                        existingPasswordEditText.requestFocus();
                        return;
                    }

                    // Check NFC availability
                    if (nfcAdapter == null) {
                        UIUtilities.showToast(ChangeMasterPassword.this, R.string.yubikey_nfc_not_available, false);
                        return;
                    }
                    if (!nfcAdapter.isEnabled()) {
                        UIUtilities.showToast(ChangeMasterPassword.this, R.string.yubikey_nfc_disabled, false);
                        return;
                    }

                    if (yubiKeyCurrentlyEnrolled && !yubiKeyEnableCheckbox.isChecked()) {
                        // Removing YubiKey — need to tap to verify it's the right key
                        waitingForYubiKeyRemove = true;
                        waitingForYubiKeyEnroll = false;
                    } else {
                        // Enrolling new YubiKey
                        waitingForYubiKeyEnroll = true;
                        waitingForYubiKeyRemove = false;
                    }

                    yubiKeyNfcPrompt.setVisibility(View.VISIBLE);
                    yubiKeyNfcPrompt.setText(waitingForYubiKeyEnroll
                            ? R.string.yubikey_tap_to_enroll
                            : R.string.yubikey_tap_now);
                }
            });
        }

        // Disable YubiKey section if NFC not available
        if (nfcAdapter == null) {
            yubiKeyEnableCheckbox.setEnabled(false);
            yubiKeyEnrollmentStatus.setText(R.string.yubikey_nfc_not_available);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (nfcAdapter != null && nfcAdapter.isEnabled()) {
            PendingIntent pendingIntent = PendingIntent.getActivity(
                    this, 0,
                    new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
                    PendingIntent.FLAG_MUTABLE);
            nfcAdapter.enableForegroundDispatch(this, pendingIntent, null, null);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (nfcAdapter != null) {
            nfcAdapter.disableForegroundDispatch(this);
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        if (intent == null) return;

        String action = intent.getAction();
        if (!NfcAdapter.ACTION_TAG_DISCOVERED.equals(action)
                && !NfcAdapter.ACTION_TECH_DISCOVERED.equals(action)
                && !NfcAdapter.ACTION_NDEF_DISCOVERED.equals(action)) {
            return;
        }

        if (!waitingForYubiKeyEnroll && !waitingForYubiKeyRemove) {
            return; // Not waiting for a tap
        }

        Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG, Tag.class);
        if (tag == null) return;

        yubiKeyEnrollProgress.setVisibility(View.VISIBLE);
        yubiKeyNfcPrompt.setText(R.string.yubikey_enrolling);

        if (waitingForYubiKeyEnroll) {
            new EnrollYubiKeyTask(tag).execute();
        } else if (waitingForYubiKeyRemove) {
            new RemoveYubiKeyTask(tag).execute();
        }
    }

    /**
     * Async task to enroll a YubiKey: provisions the OATH credential,
     * computes expected response, saves sidecar file, and re-encrypts DB.
     */
    private class EnrollYubiKeyTask extends AsyncTask<Void, Void, Boolean> {
        private final Tag tag;
        private final String existingPasswordStr;
        private final YubiKeyManager.UnlockMode mode;
        private String errorMessage;
        private String recoveryCode;

        EnrollYubiKeyTask(Tag tag) {
            this.tag = tag;
            this.existingPasswordStr = existingPasswordEditText.getText().toString();
            this.mode = selectedYubiKeyMode;
        }

        @Override
        protected Boolean doInBackground(Void... params) {
            try {
                PasswordDatabase database = ((UPMApplication) getApplication()).getPasswordDatabase();
                char[] existingPassword = existingPasswordStr.toCharArray();
                File dbFile = database.getDatabaseFile();

                // Verify existing password first
                new PasswordDatabase(dbFile, existingPassword.clone());

                // Create a pre-enrollment backup of the database
                // This is the last-resort safety net if both unlock and recovery fail
                File backupFile = new File(dbFile.getParentFile(),
                        dbFile.getName() + ".pre-yubikey-backup");
                try {
                    ((UPMApplication) getApplication()).copyFile(dbFile, backupFile,
                            ChangeMasterPassword.this);
                    Log.i("ChangeMasterPassword",
                            "Pre-enrollment backup saved: " + backupFile.getAbsolutePath());
                } catch (Exception backupErr) {
                    Log.w("ChangeMasterPassword",
                            "Could not create pre-enrollment backup", backupErr);
                }

                // Connect to YubiKey via NFC
                IsoDep isoDep = IsoDep.get(tag);
                if (isoDep == null) {
                    errorMessage = "Not a compatible NFC device";
                    return false;
                }

                isoDep.connect();
                isoDep.setTimeout(30000);

                try {
                    byte[] challenge = YubiKeyManager.generateChallenge();
                    int slot = YubiKeyManager.DEFAULT_SLOT;

                    byte[] response;
                    try {
                        response = YubiKeyManager.performChallengeResponse(isoDep, slot, challenge);
                    } catch (YubiKeyManager.YubiKeyException e) {
                        if (slot == 2) {
                            Log.w("ChangeMasterPassword", "Slot 2 failed, trying slot 1", e);
                            slot = 1;
                            isoDep.close();
                            isoDep.connect();
                            response = YubiKeyManager.performChallengeResponse(isoDep, slot, challenge);
                        } else {
                            throw e;
                        }
                    }

                    // Generate recovery code
                    recoveryCode = YubiKeyManager.generateRecoveryCode();

                    byte[] ykWrappedKey = null;
                    byte[] pwWrappedKey = null;

                    switch (mode) {
                        case PASSWORDLESS: {
                            // Generate random DB key, re-encrypt DB with it
                            byte[] dbKey = YubiKeyManager.generateDbKey();
                            char[] dbPassword = YubiKeyManager.dbKeyToPassword(dbKey);

                            database.changePassword(dbPassword);
                            database.save();

                            // Wrap DB key with YubiKey
                            ykWrappedKey = YubiKeyManager.wrapDbKeyWithYubiKey(dbKey, response);

                            // Recovery: encrypt DB key with recovery code only
                            YubiKeyManager.saveRecoveryBlobForDbKey(dbFile, recoveryCode, dbKey);

                            Arrays.fill(dbKey, (byte) 0);
                            Arrays.fill(dbPassword, '\0');
                            break;
                        }

                        case PASSWORD_OR_YUBIKEY: {
                            // Generate random DB key, re-encrypt DB with it
                            byte[] dbKey = YubiKeyManager.generateDbKey();
                            char[] dbPassword = YubiKeyManager.dbKeyToPassword(dbKey);

                            database.changePassword(dbPassword);
                            database.save();

                            // Wrap DB key with BOTH YubiKey AND password
                            ykWrappedKey = YubiKeyManager.wrapDbKeyWithYubiKey(dbKey, response);
                            pwWrappedKey = YubiKeyManager.wrapDbKeyWithPassword(dbKey, existingPassword);

                            // Recovery: encrypt DB key with recovery code only
                            YubiKeyManager.saveRecoveryBlobForDbKey(dbFile, recoveryCode, dbKey);

                            Arrays.fill(dbKey, (byte) 0);
                            Arrays.fill(dbPassword, '\0');
                            break;
                        }

                        case PASSWORD_REQUIRED:
                        default: {
                            // Original mode — combine password + YubiKey response
                            char[] combinedPassword = YubiKeyManager.combinePasswordWithYubiKeyResponse(
                                    existingPassword, response);

                            database.changePassword(combinedPassword);
                            database.save();

                            // Recovery: encrypt HMAC response with password + recovery code
                            YubiKeyManager.saveRecoveryBlob(dbFile, existingPassword, recoveryCode, response);

                            Arrays.fill(combinedPassword, '\0');
                            break;
                        }
                    }

                    // Save enrollment sidecar (v2 for modes 2/3, v1-compat for mode 1)
                    YubiKeyManager.saveEnrollmentV2(dbFile, slot, challenge, response,
                            mode, ykWrappedKey, pwWrappedKey);

                    Arrays.fill(existingPassword, '\0');

                    return true;
                } finally {
                    isoDep.close();
                }
            } catch (InvalidPasswordException e) {
                errorMessage = "Incorrect existing password";
                return false;
            } catch (YubiKeyManager.YubiKeyException e) {
                Log.e("ChangeMasterPassword", "YubiKey enrollment error", e);
                errorMessage = e.getMessage();
                return false;
            } catch (Exception e) {
                Log.e("ChangeMasterPassword", "YubiKey enrollment error", e);
                errorMessage = e.getMessage();
                return false;
            }
        }

        @Override
        protected void onPostExecute(Boolean success) {
            yubiKeyEnrollProgress.setVisibility(View.GONE);
            waitingForYubiKeyEnroll = false;

            if (success) {
                yubiKeyCurrentlyEnrolled = true;
                yubiKeyEnrollmentStatus.setText(R.string.yubikey_enrolled);
                yubiKeyNfcPrompt.setVisibility(View.GONE);
                yubiKeyEnrollButton.setText(R.string.yubikey_remove_button);

                // Show recovery code dialog — user MUST write this down
                showRecoveryCodeDialog(recoveryCode);
            } else {
                yubiKeyNfcPrompt.setText(R.string.yubikey_tap_to_enroll);
                String msg = String.format(getString(R.string.yubikey_enrollment_failed),
                        errorMessage != null ? errorMessage : "Unknown error");
                UIUtilities.showToast(ChangeMasterPassword.this, msg, true);
            }
        }
    }

    /**
     * Show a dialog with the recovery code after YubiKey enrollment.
     * The user must write this down — it's the only way to recover if the YubiKey is lost.
     */
    private void showRecoveryCodeDialog(String recoveryCode) {
        new AlertDialog.Builder(this)
            .setTitle(R.string.yubikey_recovery_title)
            .setMessage(getString(R.string.yubikey_recovery_message, recoveryCode))
            .setPositiveButton(R.string.yubikey_recovery_saved, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    UIUtilities.showToast(ChangeMasterPassword.this,
                            R.string.yubikey_enrollment_success, true);
                }
            })
            .setCancelable(false) // Force user to acknowledge
            .setIcon(android.R.drawable.ic_dialog_info)
            .show();
    }

    /**
     * Async task to remove YubiKey enrollment: re-encrypts DB with password-only,
     * then deletes the sidecar file.
     */
    private class RemoveYubiKeyTask extends AsyncTask<Void, Void, Boolean> {
        private final Tag tag;
        private final String existingPasswordStr;
        private String errorMessage;

        RemoveYubiKeyTask(Tag tag) {
            this.tag = tag;
            this.existingPasswordStr = existingPasswordEditText.getText().toString();
        }

        @Override
        protected Boolean doInBackground(Void... params) {
            try {
                PasswordDatabase database = ((UPMApplication) getApplication()).getPasswordDatabase();
                char[] existingPassword = existingPasswordStr.toCharArray();
                File dbFile = database.getDatabaseFile();

                // Load challenge for verification
                byte[] challenge = YubiKeyManager.loadChallenge(dbFile);
                if (challenge == null) {
                    errorMessage = "No enrollment found";
                    return false;
                }

                int slot = YubiKeyManager.loadSlot(dbFile);

                // Connect to YubiKey to verify it's the enrolled key
                IsoDep isoDep = IsoDep.get(tag);
                if (isoDep == null) {
                    errorMessage = "Not a compatible NFC device";
                    return false;
                }

                isoDep.connect();
                isoDep.setTimeout(30000);

                try {
                    byte[] response = YubiKeyManager.performChallengeResponse(isoDep, slot, challenge);

                    // Verify this is the correct YubiKey
                    byte[] expectedResponse = YubiKeyManager.loadExpectedResponse(dbFile);
                    if (!YubiKeyManager.verifyResponse(response, expectedResponse)) {
                        errorMessage = "Wrong YubiKey — tap the enrolled key to remove";
                        return false;
                    }

                    // Re-encrypt database with password only
                    database.changePassword(existingPassword.clone());
                    database.save();

                    // Remove enrollment and recovery files
                    YubiKeyManager.removeAllEnrollment(dbFile);

                    Arrays.fill(existingPassword, '\0');
                    return true;
                } finally {
                    isoDep.close();
                }
            } catch (YubiKeyManager.YubiKeyException e) {
                Log.e("ChangeMasterPassword", "YubiKey removal error", e);
                errorMessage = e.getMessage();
                return false;
            } catch (Exception e) {
                Log.e("ChangeMasterPassword", "YubiKey removal error", e);
                errorMessage = e.getMessage();
                return false;
            }
        }

        @Override
        protected void onPostExecute(Boolean success) {
            yubiKeyEnrollProgress.setVisibility(View.GONE);
            waitingForYubiKeyRemove = false;

            if (success) {
                yubiKeyCurrentlyEnrolled = false;
                yubiKeyEnrollmentStatus.setText(R.string.yubikey_not_enrolled);
                yubiKeyEnableCheckbox.setChecked(false);
                yubiKeyNfcPrompt.setVisibility(View.GONE);
                yubiKeyEnrollButton.setVisibility(View.GONE);
                UIUtilities.showToast(ChangeMasterPassword.this,
                        R.string.yubikey_removed_success, true);
            } else {
                yubiKeyNfcPrompt.setText(R.string.yubikey_tap_now);
                String msg = String.format(getString(R.string.yubikey_communication_error),
                        errorMessage != null ? errorMessage : "Unknown error");
                UIUtilities.showToast(ChangeMasterPassword.this, msg, true);
            }
        }
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

        // UI values captured in onPreExecute
        private String existingPasswordStr;
        private String newPassword1Str;
        private boolean doExportCsv;
        private boolean doUseModernEncryption;
        private boolean doUseChaCha20;
        private boolean doYubiKeyEnabled;

        @Override
        protected void onPreExecute() {
            // Capture all UI values on the main thread
            existingPasswordStr = existingPasswordEditText.getText().toString();
            newPassword1Str = newPassword1EditText.getText().toString();
            doExportCsv = exportCsvCheckbox.isChecked();
            doUseModernEncryption = modernEncryptionCheckbox.isChecked();
            doUseChaCha20 = useChaCha20Checkbox.isChecked();
            doYubiKeyEnabled = yubiKeyEnableCheckbox.isChecked();

            // Show appropriate message
            if (doExportCsv && newPassword1Str.isEmpty()) {
                progressDialog = ProgressDialog.show(ChangeMasterPassword.this, "",
                        getString(R.string.exporting_csv));
            } else {
                progressDialog = ProgressDialog.show(ChangeMasterPassword.this, "",
                        getString(R.string.changing_master_password));
            }
        }

        @Override
        protected Integer doInBackground(Void... params) {
            PasswordDatabase database = ((UPMApplication) getApplication()).getPasswordDatabase();

            try {
                char[] existingPassword = existingPasswordStr.toCharArray();
                File dbFile = database.getDatabaseFile();

                // Verify the existing password on background thread
                PasswordDatabase testDB = new PasswordDatabase(dbFile, existingPassword);

                // If we got here then the password was correct

                // Check if we need to export to CSV
                if (doExportCsv) {
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
                    if (newPassword1Str.isEmpty()) {
                        return RESULT_CSV_ONLY;
                    }
                }

                // If we need to change the password
                char[] newPassword = newPassword1Str.toCharArray();

                // If YubiKey is enrolled, the effective password must be combined
                // with the YubiKey response. The enrollment sidecar stays the same
                // (same challenge salt, same YubiKey), but the password portion changes.
                char[] effectiveNewPassword;
                if (yubiKeyCurrentlyEnrolled && doYubiKeyEnabled) {
                    // Need to re-derive with new password + existing YubiKey response
                    byte[] expectedResponse = YubiKeyManager.loadExpectedResponse(dbFile);
                    if (expectedResponse != null) {
                        effectiveNewPassword = YubiKeyManager.combinePasswordWithYubiKeyResponse(newPassword, expectedResponse);
                    } else {
                        effectiveNewPassword = newPassword;
                    }
                } else {
                    effectiveNewPassword = newPassword;
                }

                // Check which encryption type is selected
                boolean useModernEncryption = doUseModernEncryption;
                boolean useChaCha20 = doUseChaCha20;

                boolean isCurrentlyModern = database.isUsingModernEncryption();
                boolean isCurrentlyChaCha = database.getEncryptionAlgorithm().contains("ChaCha20");

                try {
                    // First change the password
                    database.changePassword(effectiveNewPassword);

                    // Handle encryption changes based on selection
                    if (useModernEncryption) {
                        if (!isCurrentlyModern) {
                            // Upgrade to modern from legacy
                            database.upgradeToModernEncryption(effectiveNewPassword, useChaCha20);
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

