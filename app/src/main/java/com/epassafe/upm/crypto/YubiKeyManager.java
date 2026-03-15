/*
 * Epassafe Password Manager
 * Copyright (c) 2010-2026
 *
 * YubiKey NFC HMAC-SHA1 challenge-response support for 2FA unlock.
 * Uses raw APDUs to the YubiKey OTP applet — no SDK, no registration needed.
 * The user just needs a YubiKey with HMAC-SHA1 configured in slot 1 or 2
 * (standard YubiKey 5 setup via YubiKey Manager desktop app).
 *
 * This file is part of Epassafe Password Manager.
 *
 * Epassafe Password Manager is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
package com.epassafe.upm.crypto;

import android.nfc.tech.IsoDep;
import android.util.Base64;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Manages YubiKey NFC HMAC-SHA1 challenge-response for 2FA database unlock.
 *
 * <h3>How it works (no registration required)</h3>
 * <p>The YubiKey must have HMAC-SHA1 Challenge-Response configured in one of
 * its two slots (typically slot 2). This is a one-time setup done by the user
 * via the official Yubico YubiKey Manager desktop application — our app does
 * NOT need to provision anything on the key.</p>
 *
 * <h3>Enrollment (first-time setup in Epassafe)</h3>
 * <ol>
 *   <li>User taps their YubiKey while on the "Change Master Password" screen.</li>
 *   <li>We send a random 32-byte challenge to the YubiKey via NFC APDU.</li>
 *   <li>The YubiKey computes HMAC-SHA1(its_secret, challenge) and returns 20 bytes.</li>
 *   <li>We store the challenge and the expected response in a sidecar file.</li>
 *   <li>The database is re-encrypted with SHA-256(password || yubikey_response).</li>
 * </ol>
 *
 * <h3>Unlock (every subsequent open)</h3>
 * <ol>
 *   <li>User enters password, then taps YubiKey.</li>
 *   <li>We send the stored challenge; YubiKey returns the same HMAC response.</li>
 *   <li>We verify the response matches, then combine with password to decrypt.</li>
 * </ol>
 *
 * <h3>NFC APDU protocol for YubiKey OTP applet</h3>
 * <ul>
 *   <li>SELECT: 00 A4 04 00 07 A0000005272001</li>
 *   <li>HMAC-SHA1 slot 2: 00 01 38 00 {challenge}</li>
 *   <li>HMAC-SHA1 slot 1: 00 01 30 00 {challenge}</li>
 * </ul>
 *
 * <h3>Sidecar file format (.yubikey)</h3>
 * <ul>
 *   <li>4 bytes: magic "YKCH"</li>
 *   <li>1 byte: version (currently 1)</li>
 *   <li>1 byte: slot number (1 or 2)</li>
 *   <li>32 bytes: challenge</li>
 *   <li>20 bytes: expected HMAC-SHA1 response</li>
 * </ul>
 */
public class YubiKeyManager {

    private static final String TAG = "YubiKeyManager";

    // ── YubiKey OTP applet APDU constants ────────────────────────────────

    /** AID for the YubiKey OTP applet. */
    private static final byte[] OTP_AID = {
        (byte) 0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01
    };

    /** APDU P2 for HMAC-SHA1 challenge-response on slot 1. */
    private static final byte SLOT1_HMAC = 0x30;

    /** APDU P2 for HMAC-SHA1 challenge-response on slot 2. */
    private static final byte SLOT2_HMAC = 0x38;

    /** SW1-SW2 for success. */
    private static final int SW_OK = 0x9000;

    // ── Sidecar file constants ───────────────────────────────────────────

    private static final String SIDECAR_EXTENSION = ".yubikey";
    private static final byte[] MAGIC = "YKCH".getBytes(StandardCharsets.US_ASCII);
    private static final byte FORMAT_VERSION = 1;

    /** Length of the challenge sent to the YubiKey. */
    public static final int CHALLENGE_LENGTH = 32;

    /** Length of HMAC-SHA1 output (always 20 bytes). */
    public static final int HMAC_RESPONSE_LENGTH = 20;

    /** Default slot (2) for HMAC-SHA1 challenge-response. */
    public static final int DEFAULT_SLOT = 2;

    /** Sidecar file size: magic(4) + version(1) + slot(1) + challenge(32) + response(20) = 58 */
    private static final int SIDECAR_FILE_SIZE = MAGIC.length + 1 + 1 + CHALLENGE_LENGTH + HMAC_RESPONSE_LENGTH;

    // ── Recovery file constants ──────────────────────────────────────────

    private static final String RECOVERY_EXTENSION = ".yubikey-recovery";
    private static final byte[] RECOVERY_MAGIC = "YKRC".getBytes(StandardCharsets.US_ASCII);
    private static final byte RECOVERY_VERSION = 1;

    /** Length of the human-readable recovery code (8 groups of 4 = 32 hex chars = 16 bytes entropy). */
    public static final int RECOVERY_CODE_LENGTH = 16; // 16 bytes = 128 bits of entropy

    private static final int AES_GCM_IV_LENGTH = 12;
    private static final int AES_GCM_TAG_BITS = 128;
    private static final int PBKDF2_RECOVERY_ITERATIONS = 100000;


    // ═════════════════════════════════════════════════════════════════════
    //  Sidecar file operations
    // ═════════════════════════════════════════════════════════════════════

    /** Get the sidecar file path for a given database file. */
    public static File getSidecarFile(File databaseFile) {
        return new File(databaseFile.getParentFile(), databaseFile.getName() + SIDECAR_EXTENSION);
    }

    /** Check whether a YubiKey is enrolled for the given database. */
    public static boolean isEnrolled(File databaseFile) {
        File sidecar = getSidecarFile(databaseFile);
        return sidecar.exists() && sidecar.length() == SIDECAR_FILE_SIZE;
    }

    /** Remove YubiKey enrollment (delete the sidecar file). */
    public static boolean removeEnrollment(File databaseFile) {
        File sidecar = getSidecarFile(databaseFile);
        return !sidecar.exists() || sidecar.delete();
    }

    /** Generate a new random 32-byte challenge. */
    public static byte[] generateChallenge() {
        byte[] challenge = new byte[CHALLENGE_LENGTH];
        new SecureRandom().nextBytes(challenge);
        return challenge;
    }

    /**
     * Save enrollment data to the sidecar file.
     *
     * @param databaseFile     The database file
     * @param slot             YubiKey slot (1 or 2)
     * @param challenge        The 32-byte challenge
     * @param expectedResponse The 20-byte expected HMAC-SHA1 response
     */
    public static void saveEnrollment(File databaseFile, int slot,
                                      byte[] challenge, byte[] expectedResponse) throws IOException {
        if (challenge.length != CHALLENGE_LENGTH)
            throw new IllegalArgumentException("Challenge must be " + CHALLENGE_LENGTH + " bytes");
        if (expectedResponse.length != HMAC_RESPONSE_LENGTH)
            throw new IllegalArgumentException("Response must be " + HMAC_RESPONSE_LENGTH + " bytes");
        if (slot != 1 && slot != 2)
            throw new IllegalArgumentException("Slot must be 1 or 2");

        File sidecar = getSidecarFile(databaseFile);
        try (FileOutputStream fos = new FileOutputStream(sidecar)) {
            fos.write(MAGIC);
            fos.write(FORMAT_VERSION);
            fos.write((byte) slot);
            fos.write(challenge);
            fos.write(expectedResponse);
            fos.flush();
        }
        Log.i(TAG, "YubiKey enrollment saved (" + sidecar.getName() + ", slot " + slot + ")");
    }

    /** Load the saved slot number (1 or 2), or -1 if not enrolled. */
    public static int loadSlot(File databaseFile) {
        byte[] data = readSidecar(databaseFile);
        return data != null ? (data[MAGIC.length + 1] & 0xFF) : DEFAULT_SLOT;
    }

    /** Load the 32-byte challenge from the sidecar, or null if not enrolled. */
    public static byte[] loadChallenge(File databaseFile) {
        byte[] data = readSidecar(databaseFile);
        if (data == null) return null;
        byte[] challenge = new byte[CHALLENGE_LENGTH];
        System.arraycopy(data, MAGIC.length + 2, challenge, 0, CHALLENGE_LENGTH);
        return challenge;
    }

    /** Load the 20-byte expected response from the sidecar, or null if not enrolled. */
    public static byte[] loadExpectedResponse(File databaseFile) {
        byte[] data = readSidecar(databaseFile);
        if (data == null) return null;
        byte[] response = new byte[HMAC_RESPONSE_LENGTH];
        System.arraycopy(data, MAGIC.length + 2 + CHALLENGE_LENGTH, response, 0, HMAC_RESPONSE_LENGTH);
        return response;
    }

    /** Read and validate the entire sidecar file, or return null. */
    private static byte[] readSidecar(File databaseFile) {
        File sidecar = getSidecarFile(databaseFile);
        if (!sidecar.exists() || sidecar.length() != SIDECAR_FILE_SIZE) return null;

        try (FileInputStream fis = new FileInputStream(sidecar)) {
            byte[] data = new byte[SIDECAR_FILE_SIZE];
            if (fis.read(data) != SIDECAR_FILE_SIZE) return null;

            // Verify magic
            for (int i = 0; i < MAGIC.length; i++) {
                if (data[i] != MAGIC[i]) return null;
            }
            // Verify version
            if (data[MAGIC.length] != FORMAT_VERSION) return null;

            return data;
        } catch (IOException e) {
            Log.e(TAG, "Error reading sidecar file", e);
            return null;
        }
    }


    // ═════════════════════════════════════════════════════════════════════
    //  Raw NFC APDU communication with YubiKey OTP applet
    // ═════════════════════════════════════════════════════════════════════

    /**
     * Perform HMAC-SHA1 challenge-response with a YubiKey over NFC.
     *
     * <p>This sends raw ISO 7816-4 APDUs to the YubiKey's OTP applet.
     * No SDK, no registration, no provisioning needed — the YubiKey just
     * needs HMAC-SHA1 configured in the target slot.
     *
     * @param isoDep    An already-connected IsoDep instance
     * @param slot      YubiKey slot (1 or 2)
     * @param challenge The challenge bytes (up to 64 bytes, typically 32)
     * @return The 20-byte HMAC-SHA1 response
     * @throws IOException if NFC communication fails
     * @throws YubiKeyException if the YubiKey returns an error
     */
    public static byte[] performChallengeResponse(IsoDep isoDep, int slot, byte[] challenge)
            throws IOException, YubiKeyException {

        // Step 1: SELECT the OTP applet
        byte[] selectApdu = buildSelectApdu(OTP_AID);
        byte[] selectResponse = isoDep.transceive(selectApdu);
        checkSW(selectResponse, "SELECT OTP applet");

        // Step 2: Send HMAC-SHA1 challenge
        byte slotP2 = (slot == 1) ? SLOT1_HMAC : SLOT2_HMAC;
        byte[] hmacApdu = buildHmacApdu(slotP2, challenge);
        byte[] hmacResponse = isoDep.transceive(hmacApdu);
        checkSW(hmacResponse, "HMAC-SHA1 challenge-response");

        // Extract the 20-byte HMAC result (response minus 2-byte status word)
        if (hmacResponse.length < HMAC_RESPONSE_LENGTH + 2) {
            throw new YubiKeyException("Response too short: expected at least "
                    + (HMAC_RESPONSE_LENGTH + 2) + " bytes, got " + hmacResponse.length);
        }

        byte[] result = new byte[HMAC_RESPONSE_LENGTH];
        System.arraycopy(hmacResponse, 0, result, 0, HMAC_RESPONSE_LENGTH);

        Log.i(TAG, "HMAC-SHA1 challenge-response successful (slot " + slot + ")");
        return result;
    }

    /**
     * Build a SELECT APDU: 00 A4 04 00 {len} {AID}
     */
    private static byte[] buildSelectApdu(byte[] aid) {
        byte[] apdu = new byte[5 + aid.length];
        apdu[0] = 0x00; // CLA
        apdu[1] = (byte) 0xA4; // INS: SELECT
        apdu[2] = 0x04; // P1: Select by name
        apdu[3] = 0x00; // P2
        apdu[4] = (byte) aid.length; // Lc
        System.arraycopy(aid, 0, apdu, 5, aid.length);
        return apdu;
    }

    /**
     * Build an HMAC-SHA1 challenge APDU: 00 01 {slotP2} 00 {len} {challenge}
     */
    private static byte[] buildHmacApdu(byte slotP2, byte[] challenge) {
        // Pad challenge to exactly 64 bytes (YubiKey expects this)
        byte[] padded = new byte[64];
        System.arraycopy(challenge, 0, padded, 0, Math.min(challenge.length, 64));

        byte[] apdu = new byte[5 + padded.length];
        apdu[0] = 0x00; // CLA
        apdu[1] = 0x01; // INS: API request
        apdu[2] = slotP2; // P2: slot + HMAC flag
        apdu[3] = 0x00; // P1
        apdu[4] = (byte) padded.length; // Lc
        System.arraycopy(padded, 0, apdu, 5, padded.length);
        return apdu;
    }

    /**
     * Check the status word (last 2 bytes) of an APDU response.
     */
    private static void checkSW(byte[] response, String operation) throws YubiKeyException {
        if (response == null || response.length < 2) {
            throw new YubiKeyException(operation + ": empty response from YubiKey");
        }
        int sw = ((response[response.length - 2] & 0xFF) << 8) | (response[response.length - 1] & 0xFF);
        if (sw != SW_OK) {
            throw new YubiKeyException(String.format(
                    "%s failed: SW=%04X (expected 9000). Is HMAC-SHA1 configured in this slot?",
                    operation, sw));
        }
    }

    /**
     * Custom exception for YubiKey communication errors.
     */
    public static class YubiKeyException extends Exception {
        public YubiKeyException(String message) {
            super(message);
        }
    }


    // ═════════════════════════════════════════════════════════════════════
    //  Key combination — merge password + YubiKey response
    // ═════════════════════════════════════════════════════════════════════

    /**
     * Combine the master password with the YubiKey HMAC-SHA1 response to
     * produce strengthened key material for PBKDF2.
     *
     * <p>Method: SHA-256(password_bytes ‖ hmac_response) → Base64 → char[]
     *
     * <p>This ensures the derived encryption key depends on BOTH the user's
     * password and the physical YubiKey. The SHA-256 intermediate hash
     * prevents length-extension attacks, and the Base64 encoding produces
     * a char[] suitable for the existing PBKDF2 key derivation.
     *
     * @param password      The user's master password
     * @param hmacResponse  The 20-byte HMAC-SHA1 response from the YubiKey
     * @return Combined key material as char[]
     */
    public static char[] combinePasswordWithYubiKeyResponse(char[] password, byte[] hmacResponse) {
        try {
            byte[] passwordBytes = new String(password).getBytes(StandardCharsets.UTF_8);

            // Concatenate password bytes and HMAC response
            byte[] combined = new byte[passwordBytes.length + hmacResponse.length];
            System.arraycopy(passwordBytes, 0, combined, 0, passwordBytes.length);
            System.arraycopy(hmacResponse, 0, combined, passwordBytes.length, hmacResponse.length);

            // Hash with SHA-256
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(combined);

            // Securely clear intermediates
            Arrays.fill(passwordBytes, (byte) 0);
            Arrays.fill(combined, (byte) 0);

            // Encode as Base64 → char[] for PBKDF2 input
            String encoded = Base64.encodeToString(hash, Base64.NO_WRAP | Base64.NO_PADDING);
            Arrays.fill(hash, (byte) 0);

            return encoded.toCharArray();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Verify that two HMAC responses match using constant-time comparison.
     */
    public static boolean verifyResponse(byte[] actual, byte[] expected) {
        if (actual == null || expected == null) return false;
        return MessageDigest.isEqual(actual, expected);
    }


    // ═════════════════════════════════════════════════════════════════════
    //  Recovery code — allows unlock if YubiKey is lost
    // ═════════════════════════════════════════════════════════════════════
    //
    //  On enrollment we generate a random recovery code and show it once.
    //  We encrypt the YubiKey HMAC response with a key derived from
    //  (password + recovery_code) via PBKDF2, and store the resulting blob
    //  in a .yubikey-recovery file. If the user loses their YubiKey they
    //  enter password + recovery code → we decrypt the HMAC response →
    //  reconstruct the combined key → decrypt the database → re-encrypt
    //  with password only → delete enrollment files.
    //

    /** Get the recovery file path for a given database file. */
    public static File getRecoveryFile(File databaseFile) {
        return new File(databaseFile.getParentFile(), databaseFile.getName() + RECOVERY_EXTENSION);
    }

    /** Check whether a recovery file exists. */
    public static boolean hasRecoveryFile(File databaseFile) {
        return getRecoveryFile(databaseFile).exists();
    }

    /**
     * Generate a human-readable recovery code.
     * Format: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX (32 hex chars, 128-bit entropy).
     *
     * @return The recovery code string (with dashes for readability)
     */
    public static String generateRecoveryCode() {
        byte[] bytes = new byte[RECOVERY_CODE_LENGTH];
        new SecureRandom().nextBytes(bytes);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0 && i % 2 == 0) sb.append('-');
            sb.append(String.format("%02X", bytes[i]));
        }
        return sb.toString();
    }

    /**
     * Normalize a recovery code for cryptographic use (strip dashes, uppercase).
     */
    private static String normalizeRecoveryCode(String recoveryCode) {
        return recoveryCode.replace("-", "").replace(" ", "").toUpperCase();
    }

    /**
     * Save a recovery blob: the YubiKey HMAC response encrypted with a key
     * derived from (password + recovery_code).
     *
     * <p>File format:
     * <ul>
     *   <li>4 bytes: magic "YKRC"</li>
     *   <li>1 byte: version</li>
     *   <li>16 bytes: PBKDF2 salt</li>
     *   <li>12 bytes: AES-GCM IV</li>
     *   <li>remaining: AES-GCM ciphertext (20-byte HMAC response + 16-byte auth tag)</li>
     * </ul>
     *
     * @param databaseFile  The database file
     * @param password      The user's master password
     * @param recoveryCode  The recovery code (with or without dashes)
     * @param hmacResponse  The 20-byte YubiKey HMAC response to protect
     */
    public static void saveRecoveryBlob(File databaseFile, char[] password,
                                        String recoveryCode, byte[] hmacResponse) throws Exception {
        String normalized = normalizeRecoveryCode(recoveryCode);

        // Derive encryption key from password + recovery code
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        char[] combined = combineForRecovery(password, normalized);
        PBEKeySpec spec = new PBEKeySpec(combined, salt, PBKDF2_RECOVERY_ITERATIONS, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        Arrays.fill(combined, '\0');
        Arrays.fill(keyBytes, (byte) 0);

        // Encrypt the HMAC response with AES-GCM
        byte[] iv = new byte[AES_GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(AES_GCM_TAG_BITS, iv));
        byte[] ciphertext = cipher.doFinal(hmacResponse);

        // Write recovery file
        File recoveryFile = getRecoveryFile(databaseFile);
        try (FileOutputStream fos = new FileOutputStream(recoveryFile)) {
            fos.write(RECOVERY_MAGIC);
            fos.write(RECOVERY_VERSION);
            fos.write(salt);
            fos.write(iv);
            fos.write(ciphertext);
            fos.flush();
        }
        Log.i(TAG, "Recovery blob saved (" + recoveryFile.getName() + ")");
    }

    /**
     * Decrypt the recovery blob to recover the YubiKey HMAC response.
     *
     * @param databaseFile  The database file
     * @param password      The user's master password
     * @param recoveryCode  The recovery code entered by the user
     * @return The 20-byte HMAC response, or null if decryption fails
     */
    public static byte[] decryptRecoveryBlob(File databaseFile, char[] password,
                                             String recoveryCode) {
        File recoveryFile = getRecoveryFile(databaseFile);
        if (!recoveryFile.exists()) return null;

        try (FileInputStream fis = new FileInputStream(recoveryFile)) {
            // Read and validate header
            byte[] magic = new byte[RECOVERY_MAGIC.length];
            if (fis.read(magic) != magic.length) return null;
            if (!Arrays.equals(magic, RECOVERY_MAGIC)) return null;

            int version = fis.read();
            if (version != RECOVERY_VERSION) return null;

            // Read salt
            byte[] salt = new byte[16];
            if (fis.read(salt) != salt.length) return null;

            // Read IV
            byte[] iv = new byte[AES_GCM_IV_LENGTH];
            if (fis.read(iv) != iv.length) return null;

            // Read ciphertext (rest of file)
            byte[] ciphertext = new byte[fis.available()];
            if (fis.read(ciphertext) != ciphertext.length) return null;

            // Derive decryption key
            String normalized = normalizeRecoveryCode(recoveryCode);
            char[] combined = combineForRecovery(password, normalized);
            PBEKeySpec spec = new PBEKeySpec(combined, salt, PBKDF2_RECOVERY_ITERATIONS, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
            Arrays.fill(combined, '\0');
            Arrays.fill(keyBytes, (byte) 0);

            // Decrypt
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(AES_GCM_TAG_BITS, iv));
            return cipher.doFinal(ciphertext);

        } catch (Exception e) {
            Log.e(TAG, "Failed to decrypt recovery blob", e);
            return null;
        }
    }

    /** Remove the recovery file. */
    public static boolean removeRecoveryFile(File databaseFile) {
        File f = getRecoveryFile(databaseFile);
        return !f.exists() || f.delete();
    }

    /** Remove both enrollment and recovery files. */
    public static boolean removeAllEnrollment(File databaseFile) {
        boolean a = removeEnrollment(databaseFile);
        boolean b = removeRecoveryFile(databaseFile);
        return a && b;
    }

    /** Combine password + recovery code into a single char[] for PBKDF2. */
    private static char[] combineForRecovery(char[] password, String recoveryCode) {
        char[] rcChars = recoveryCode.toCharArray();
        char[] combined = new char[password.length + 1 + rcChars.length];
        System.arraycopy(password, 0, combined, 0, password.length);
        combined[password.length] = ':';
        System.arraycopy(rcChars, 0, combined, password.length + 1, rcChars.length);
        Arrays.fill(rcChars, '\0');
        return combined;
    }
}

