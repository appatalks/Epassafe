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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
package com.epassafe.upm;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Log;
import android.view.KeyEvent;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.View.OnKeyListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import com.epassafe.upm.crypto.InvalidPasswordException;
import com.epassafe.upm.crypto.YubiKeyManager;
import com.epassafe.upm.database.PasswordDatabase;
import com.epassafe.upm.database.ProblemReadingDatabaseFile;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * This Activity is responsible for prompting the user to enter their master
 * password and then decrypting the database. If the correct password is entered
 * then the AccountList Activity is loaded.
 */
public class EnterMasterPassword extends Activity implements OnClickListener {

    public static PasswordDatabase decryptedPasswordDatabase;
    public static File databaseFileToDecrypt;

    private EditText passwordField;
    private DecryptDatabase decryptDatabaseTask;
    private ProgressDialog progressDialog;

    // YubiKey NFC support
    private boolean yubiKeyEnrolled = false;
    private boolean yubiKeyResponseReceived = false;
    private byte[] yubiKeyResponse = null;
    private NfcAdapter nfcAdapter;
    private LinearLayout yubiKeySection;
    private TextView yubiKeyStatus;
    private TextView yubiKeyResult;
    private ProgressBar yubiKeyProgress;

    /* SAVE DATABASE BACKUP FILE ON EXIT */
    /* AUTOMATIC BACKUP TO FILE aupm.db THAN MANUAL BACKUP upm.db*/
    @Override
    public void onBackPressed()
    {
    	File fileOnSDCard = new File(getExternalFilesDir("database"), Utilities.AUTOMATIC_DATABASE_FILE);
        File databaseFile = Utilities.getDatabaseFile(this);
        if (((UPMApplication) getApplication()).copyFile(databaseFile, fileOnSDCard, this)) {
            String message = String.format(getString(R.string.backup_complete), fileOnSDCard.getAbsolutePath());
            UIUtilities.showToast(this, message, false);
        }
        /* System.exit(0);  // Annoying Exit Bug */
        this.finishAffinity();              // Doesn't seem to fully exit but leaving to close tasks
        EnterMasterPassword.this.finish();  // TESTING for cleaner exit
        finishAndRemoveTask();              // TESTING for cleaner exit
    }
    /* SAVE DATABASE ON EXIT END */
    
	@SuppressWarnings("deprecation")
	@Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.enter_master_password);
        
        passwordField = findViewById(R.id.password);
        passwordField.setText(null);

        // Make this class the listener for the click event on the OK button
        Button okButton = findViewById(R.id.master_password_open_button);
        okButton.setOnClickListener(this);

        passwordField.setOnKeyListener(new OnKeyListener() {
            public boolean onKey(View v, int keyCode, KeyEvent event) {
                if ((event.getAction() == KeyEvent.ACTION_DOWN) && (keyCode == KeyEvent.KEYCODE_ENTER)) {
                    openDatabase();
                    return true;
                }
                return false;
            }
        });

        // YubiKey NFC setup
        yubiKeySection = findViewById(R.id.yubikey_section);
        yubiKeyStatus = findViewById(R.id.yubikey_status);
        yubiKeyResult = findViewById(R.id.yubikey_result);
        yubiKeyProgress = findViewById(R.id.yubikey_progress);

        // Check if YubiKey is enrolled for this database
        if (databaseFileToDecrypt != null && YubiKeyManager.isEnrolled(databaseFileToDecrypt)) {
            yubiKeyEnrolled = true;
            yubiKeySection.setVisibility(View.VISIBLE);
            yubiKeyStatus.setText(R.string.yubikey_tap_to_unlock);

            // Show "Lost YubiKey?" link if recovery file exists
            TextView lostKeyLink = findViewById(R.id.yubikey_lost_key);
            if (lostKeyLink != null && YubiKeyManager.hasRecoveryFile(databaseFileToDecrypt)) {
                lostKeyLink.setVisibility(View.VISIBLE);
                lostKeyLink.setOnClickListener(new OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        showRecoveryDialog();
                    }
                });
            }
        }

        // Initialize NFC adapter
        nfcAdapter = NfcAdapter.getDefaultAdapter(this);
        if (yubiKeyEnrolled && nfcAdapter == null) {
            yubiKeyStatus.setText(R.string.yubikey_nfc_not_available);
            yubiKeyStatus.setTextColor(0xFFFF0000);
        } else if (yubiKeyEnrolled && !nfcAdapter.isEnabled()) {
            yubiKeyStatus.setText(R.string.yubikey_nfc_disabled);
            yubiKeyStatus.setTextColor(0xFFFF9800);
        }

        decryptDatabaseTask = (DecryptDatabase) getLastNonConfigurationInstance();
        if (decryptDatabaseTask != null) {
            // Associate the async task with the new activity
            decryptDatabaseTask.setActivity(this);

            // If the decryptDatabaseTask is running display the progress
            // dialog. This can happen if the screen was rotated while the
            // background task is running.
            if (decryptDatabaseTask.getStatus() == AsyncTask.Status.RUNNING) {
                progressDialog = ProgressDialog.show(this, "",
                        this.getString(R.string.decrypting_db));
            }
        }
    }

    public ProgressDialog getProgressDialog() {
        return this.progressDialog;
    }

    @Override
    public void onClick(View v) {
        if (v.getId() == R.id.master_password_open_button) {
            if (yubiKeyEnrolled && !yubiKeyResponseReceived) {
                // YubiKey is required but hasn't been tapped yet
                UIUtilities.showToast(this, R.string.yubikey_require_tap, false);
                return;
            }
            openDatabase();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        // Enable NFC foreground dispatch so YubiKey taps come to this activity
        if (nfcAdapter != null && nfcAdapter.isEnabled()) {
            android.app.PendingIntent pendingIntent = android.app.PendingIntent.getActivity(
                    this, 0,
                    new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
                    android.app.PendingIntent.FLAG_MUTABLE);
            nfcAdapter.enableForegroundDispatch(this, pendingIntent, null, null);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        // Disable NFC foreground dispatch
        if (nfcAdapter != null) {
            nfcAdapter.disableForegroundDispatch(this);
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);

        // Handle NFC YubiKey tap
        if (intent == null) return;
        String action = intent.getAction();
        if (NfcAdapter.ACTION_TAG_DISCOVERED.equals(action)
                || NfcAdapter.ACTION_TECH_DISCOVERED.equals(action)
                || NfcAdapter.ACTION_NDEF_DISCOVERED.equals(action)) {

            if (!yubiKeyEnrolled) {
                // Not enrolled, ignore NFC taps
                return;
            }

            // Check password is entered
            String passwordStr = passwordField.getText().toString();
            if (passwordStr.isEmpty()) {
                UIUtilities.showToast(this, R.string.yubikey_password_first, false);
                return;
            }

            Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG, Tag.class);
            if (tag == null) return;

            // Show progress
            if (yubiKeyProgress != null) yubiKeyProgress.setVisibility(View.VISIBLE);
            if (yubiKeyStatus != null) yubiKeyStatus.setText(R.string.yubikey_verifying);

            // Process YubiKey on background thread
            new ProcessYubiKeyTask(tag).execute();
        }
    }

    /**
     * Background task to communicate with YubiKey via NFC and perform
     * HMAC-SHA1 challenge-response.
     */
    private class ProcessYubiKeyTask extends AsyncTask<Void, Void, byte[]> {
        private final Tag tag;
        private String errorMessage;

        ProcessYubiKeyTask(Tag tag) {
            this.tag = tag;
        }

        @Override
        protected byte[] doInBackground(Void... params) {
            try {
                // Load challenge from sidecar file
                byte[] challenge = YubiKeyManager.loadChallenge(databaseFileToDecrypt);
                if (challenge == null) {
                    errorMessage = "No enrollment data found";
                    return null;
                }

                int slot = YubiKeyManager.loadSlot(databaseFileToDecrypt);

                // Connect to YubiKey via NFC
                IsoDep isoDep = IsoDep.get(tag);
                if (isoDep == null) {
                    errorMessage = "Not a YubiKey NFC device";
                    return null;
                }

                isoDep.connect();
                isoDep.setTimeout(30000); // 30 second timeout

                try {
                    // Send HMAC-SHA1 challenge-response via raw APDU
                    byte[] response = YubiKeyManager.performChallengeResponse(isoDep, slot, challenge);

                    // Verify against expected response
                    byte[] expectedResponse = YubiKeyManager.loadExpectedResponse(databaseFileToDecrypt);
                    if (expectedResponse != null && !YubiKeyManager.verifyResponse(response, expectedResponse)) {
                        errorMessage = getString(R.string.yubikey_wrong_key);
                        return null;
                    }

                    return response;
                } finally {
                    isoDep.close();
                }
            } catch (YubiKeyManager.YubiKeyException e) {
                Log.e("EnterMasterPassword", "YubiKey error", e);
                errorMessage = e.getMessage();
                return null;
            } catch (Exception e) {
                Log.e("EnterMasterPassword", "YubiKey error", e);
                errorMessage = e.getMessage();
                return null;
            }
        }

        @Override
        protected void onPostExecute(byte[] response) {
            if (yubiKeyProgress != null) yubiKeyProgress.setVisibility(View.GONE);

            if (response != null) {
                // Success! Store the response
                yubiKeyResponse = response;
                yubiKeyResponseReceived = true;

                if (yubiKeyStatus != null) {
                    yubiKeyStatus.setText(R.string.yubikey_verified);
                    yubiKeyStatus.setTextColor(0xFF4CAF50);
                }
                if (yubiKeyResult != null) {
                    yubiKeyResult.setText(R.string.yubikey_verified);
                    yubiKeyResult.setVisibility(View.VISIBLE);
                }

                // Auto-trigger database open
                openDatabase();
            } else {
                // Failure
                if (yubiKeyStatus != null) {
                    yubiKeyStatus.setText(R.string.yubikey_tap_to_unlock);
                }
                String msg = String.format(getString(R.string.yubikey_communication_error),
                        errorMessage != null ? errorMessage : "Unknown error");
                UIUtilities.showToast(EnterMasterPassword.this, msg, true);
            }
        }
    }

    /**
     * Show a dialog prompting for the recovery code when the user has lost their YubiKey.
     */
    private void showRecoveryDialog() {
        final EditText recoveryInput = new EditText(this);
        recoveryInput.setHint(R.string.yubikey_recovery_code_hint);
        recoveryInput.setInputType(android.text.InputType.TYPE_CLASS_TEXT
                | android.text.InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS);
        recoveryInput.setPadding(40, 20, 40, 20);

        new AlertDialog.Builder(this)
            .setTitle(R.string.yubikey_lost_key_title)
            .setMessage(R.string.yubikey_lost_key_message)
            .setView(recoveryInput)
            .setPositiveButton(R.string.yubikey_recover_button, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    String code = recoveryInput.getText().toString().trim();
                    if (code.isEmpty()) {
                        UIUtilities.showToast(EnterMasterPassword.this,
                                R.string.yubikey_recovery_code_required, false);
                        return;
                    }
                    String pw = passwordField.getText().toString();
                    if (pw.isEmpty()) {
                        UIUtilities.showToast(EnterMasterPassword.this,
                                R.string.yubikey_password_first, false);
                        return;
                    }
                    // Run recovery in background
                    new RecoverWithCodeTask(pw.toCharArray(), code).execute();
                }
            })
            .setNegativeButton(R.string.cancel, null)
            .show();
    }

    /**
     * Background task to recover from a lost YubiKey using the recovery code.
     * Decrypts recovery blob → reconstructs combined key → opens DB →
     * re-encrypts with password only → deletes enrollment files.
     */
    private class RecoverWithCodeTask extends AsyncTask<Void, Void, Boolean> {
        private final char[] password;
        private final String recoveryCode;
        private String errorMessage;

        RecoverWithCodeTask(char[] password, String recoveryCode) {
            this.password = password;
            this.recoveryCode = recoveryCode;
        }

        @Override
        protected Boolean doInBackground(Void... params) {
            try {
                // Decrypt the recovery blob to get the HMAC response
                byte[] hmacResponse = YubiKeyManager.decryptRecoveryBlob(
                        databaseFileToDecrypt, password, recoveryCode);
                if (hmacResponse == null) {
                    errorMessage = "Invalid recovery code or password";
                    return false;
                }

                // Reconstruct the combined key (password + HMAC response)
                char[] combinedKey = YubiKeyManager.combinePasswordWithYubiKeyResponse(
                        password, hmacResponse);

                // Open the database with the combined key
                decryptedPasswordDatabase = new PasswordDatabase(
                        databaseFileToDecrypt, combinedKey);

                // Re-encrypt with password only (remove YubiKey requirement)
                decryptedPasswordDatabase.changePassword(password.clone());
                decryptedPasswordDatabase.save();

                // Delete enrollment and recovery files
                YubiKeyManager.removeAllEnrollment(databaseFileToDecrypt);

                // Clean up
                Arrays.fill(combinedKey, '\0');
                Arrays.fill(hmacResponse, (byte) 0);

                return true;
            } catch (Exception e) {
                Log.e("EnterMasterPassword", "Recovery failed", e);
                errorMessage = e.getMessage();
                return false;
            } finally {
                Arrays.fill(password, '\0');
            }
        }

        @Override
        protected void onPostExecute(Boolean success) {
            if (success) {
                UIUtilities.showToast(EnterMasterPassword.this,
                        R.string.yubikey_recovery_success, true);
                // Database is now open and re-encrypted without YubiKey
                setResult(RESULT_OK);
                finish();
            } else {
                UIUtilities.showToast(EnterMasterPassword.this,
                        String.format(getString(R.string.yubikey_recovery_failed),
                                errorMessage != null ? errorMessage : "Unknown error"),
                        true);
            }
        }
    }

    @Override
    protected void onStop() {
        super.onStop();

        // If the activity is being stopped while the progress dialog is
        // displayed (e.g. the screen is being rotated) dismiss it here.
        // We'll display it again in the new activity.
        if (progressDialog != null) {
            progressDialog.dismiss();
        }
    }

    @Override
    public Object onRetainNonConfigurationInstance () {
        // Disassociate the background task from the activity. A new one will
        // be created imminently.
        if (decryptDatabaseTask != null) {
            decryptDatabaseTask.setActivity(null);
        }
        return decryptDatabaseTask;
    }

    private void openDatabase() {
        // Show the progress dialog
        progressDialog = ProgressDialog.show(
                this, "", this.getString(R.string.decrypting_db));

        // In certain situations databaseFileToDecrypt can be null
        if (EnterMasterPassword.databaseFileToDecrypt == null) {
            Log.w("EnterMasterPassword", "databaseFileToDecrypt was unexpectedly null");
            EnterMasterPassword.databaseFileToDecrypt = Utilities.getDatabaseFile(this);
        }

        // Create and execute the background task that will decrypt the db
        // Pass YubiKey response if available
        decryptDatabaseTask = new DecryptDatabase(this);
        decryptDatabaseTask.setYubiKeyResponse(yubiKeyResponse);
        decryptDatabaseTask.execute();
    }

    public EditText getPasswordField() {
        return passwordField;
    }

    // Show a progress dialog and then start the decrypting of the
    // db in a separate thread
    private static class DecryptDatabase extends AsyncTask<Void, Void, Integer> {

        private static final int ERROR_INVALID_PASSWORD = 1;
        private static final int ERROR_GENERIC_ERROR = 2;
        private static final int ERROR_DATABASE_CORRUPTED = 3;

        private EnterMasterPassword activity;
        private String errorMessage;
        private char[] password;
        private byte[] yubiKeyResponse;
        private boolean passwordProcessed = false;

        public DecryptDatabase(EnterMasterPassword activity) {
            this.activity = activity;
        }

        public void setYubiKeyResponse(byte[] response) {
            this.yubiKeyResponse = response;
        }

        @Override
        protected void onPreExecute() {
            // Get password securely
            password = activity.getPasswordField().getText().toString().toCharArray();
        }

        @Override
        protected Integer doInBackground(Void... params) {
            int errorCode = 0;
            try {
                // Create a defensive copy of the password for decryption
                char[] passwordCopy = null;
                char[] effectivePassword = null;
                try {
                    // Make a copy of the password to prevent concurrent modification
                    passwordCopy = new char[password.length];
                    System.arraycopy(password, 0, passwordCopy, 0, password.length);

                    // If YubiKey response is available, combine with password
                    if (yubiKeyResponse != null && yubiKeyResponse.length > 0) {
                        effectivePassword = YubiKeyManager.combinePasswordWithYubiKeyResponse(passwordCopy, yubiKeyResponse);
                        // Clear the plain password copy since we're using the combined one
                        Arrays.fill(passwordCopy, '\0');
                    } else {
                        effectivePassword = passwordCopy;
                    }

                    // Attempt to decrypt the database with the effective password
                    decryptedPasswordDatabase =
                            new PasswordDatabase(databaseFileToDecrypt, effectivePassword);

                    // Mark that we've processed the password
                    passwordProcessed = true;
                } finally {
                    // Clean up password copies securely
                    if (passwordCopy != null) {
                        Arrays.fill(passwordCopy, '\0');
                    }
                    if (effectivePassword != null && effectivePassword != passwordCopy) {
                        Arrays.fill(effectivePassword, '\0');
                    }
                    if (yubiKeyResponse != null) {
                        Arrays.fill(yubiKeyResponse, (byte) 0);
                    }
                }
            } catch (InvalidPasswordException e) {
                Log.e("EnterMasterPassword", "Invalid password: " + e.getMessage(), e);
                errorMessage = e.getMessage();
                errorCode = ERROR_INVALID_PASSWORD;
            } catch (IOException e) {
                Log.e("EnterMasterPassword", "IO error: " + e.getMessage(), e);
                errorMessage = e.getMessage();
                errorCode = ERROR_GENERIC_ERROR;
            } catch (GeneralSecurityException e) {
                Log.e("EnterMasterPassword", "Security error: " + e.getMessage(), e);
                errorMessage = e.getMessage();
                errorCode = ERROR_GENERIC_ERROR;
            } catch (ProblemReadingDatabaseFile e) {
                Log.e("EnterMasterPassword", "Database corrupted: " + e.getMessage(), e);
                errorMessage = e.getMessage();
                errorCode = ERROR_DATABASE_CORRUPTED;
            } catch (Exception e) {
                // Catch any unexpected exceptions to prevent app crashes
                Log.e("EnterMasterPassword", "Unexpected error: " + e.getMessage(), e);
                errorMessage = e.getMessage();
                errorCode = ERROR_GENERIC_ERROR;
            } finally {
                // Always clear the original password from memory once we're done with it
                if (password != null) {
                    Arrays.fill(password, '\0');
                }
            }
            
            return errorCode;
        }

        @Override
        protected void onPostExecute(Integer result) {
            // Ensure the progress dialog is dismissed regardless of outcome
            try {
                if (activity != null && activity.getProgressDialog() != null) {
                    activity.getProgressDialog().dismiss();
                }
            } catch (Exception e) {
                Log.w("EnterMasterPassword", "Error dismissing dialog", e);
            }

            // If activity is gone, no point continuing
            if (activity == null) {
                return;
            }

            switch (result) {
                case ERROR_INVALID_PASSWORD:
                    Toast toast = Toast.makeText(activity, R.string.invalid_password, Toast.LENGTH_SHORT);
                    toast.show();

                    // Set focus back to the password and select all characters
                    activity.getPasswordField().requestFocus();
                    activity.getPasswordField().selectAll();
                    break;

                case ERROR_DATABASE_CORRUPTED:
                    String corruptMessage = String.format(
                            activity.getString(R.string.generic_error_with_message),
                            "Database appears to be corrupted: " + errorMessage);
                    UIUtilities.showToast(activity, corruptMessage, true);
                    break;

                case ERROR_GENERIC_ERROR:
                    String message = String.format(
                            activity.getString(R.string.generic_error_with_message),
                            errorMessage);
                    UIUtilities.showToast(activity, message, true);
                    break;

                default:
                    // Success! Set result and finish activity
                    if (passwordProcessed && decryptedPasswordDatabase != null) {
                        activity.setResult(RESULT_OK);
                        activity.finish();
                    } else {
                        // This should not happen - we got success but database wasn't loaded
                        Log.e("EnterMasterPassword", "Database not properly loaded despite success code");
                        UIUtilities.showToast(activity, "Error loading database. Please try again.", true);
                    }
                    break;
            }
        }

        private void setActivity(EnterMasterPassword activity) {
            this.activity = activity;
        }
    }

}
