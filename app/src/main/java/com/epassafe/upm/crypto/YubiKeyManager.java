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

import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import android.hardware.usb.UsbManager;
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

    // ── Unlock modes ─────────────────────────────────────────────────────

    /** How the YubiKey interacts with password-based unlock. */
    public enum UnlockMode {
        /** Password + YubiKey both required (current default). DB key = SHA-256(pw||yk). */
        PASSWORD_REQUIRED(0),
        /** YubiKey only — no password needed. DB key = random, wrapped by YubiKey. */
        PASSWORDLESS(1),
        /** Either password alone OR YubiKey alone. DB key = random, wrapped by both. */
        PASSWORD_OR_YUBIKEY(2);

        public final int code;
        UnlockMode(int code) { this.code = code; }
        public static UnlockMode fromCode(int code) {
            for (UnlockMode m : values()) if (m.code == code) return m;
            return PASSWORD_REQUIRED;
        }
    }

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
    private static final byte FORMAT_VERSION_1 = 1;
    private static final byte FORMAT_VERSION_2 = 2;

    /** Length of the challenge sent to the YubiKey. */
    public static final int CHALLENGE_LENGTH = 32;

    /** Length of HMAC-SHA1 output (always 20 bytes). */
    public static final int HMAC_RESPONSE_LENGTH = 20;

    /** Default slot (2) for HMAC-SHA1 challenge-response. */
    public static final int DEFAULT_SLOT = 2;

    /** V1 sidecar file size: magic(4) + version(1) + slot(1) + challenge(32) + response(20) = 58 */
    private static final int SIDECAR_V1_SIZE = MAGIC.length + 1 + 1 + CHALLENGE_LENGTH + HMAC_RESPONSE_LENGTH;

    /** V2 header size: v1 header(58) + mode(1) = 59, followed by variable-length blobs */
    private static final int SIDECAR_V2_HEADER_SIZE = SIDECAR_V1_SIZE + 1;

    /** Length of random DB key used for PASSWORDLESS and PASSWORD_OR_YUBIKEY modes. */
    public static final int DB_KEY_LENGTH = 32;

    /** HKDF info string for deriving YubiKey wrapping key. */
    private static final byte[] HKDF_INFO = "epassafe-yk-wrap".getBytes(StandardCharsets.US_ASCII);

    /** AES-GCM parameters for key wrapping. */
    private static final int WRAP_IV_LENGTH = 12;
    private static final int WRAP_SALT_LENGTH = 16;
    private static final int WRAP_TAG_BITS = 128;

    /** PBKDF2 iterations for password-based wrapping key (mode 3). */
    private static final int PBKDF2_WRAP_ITERATIONS = 310000;

    /** Blob tags in v2 sidecar. */
    private static final byte BLOB_TAG_YK_WRAPPED_KEY = 0x01;
    private static final byte BLOB_TAG_PW_WRAPPED_KEY = 0x02;

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
    //  Sidecar file operations (v1 + v2)
    // ═════════════════════════════════════════════════════════════════════

    /** Get the sidecar file path for a given database file. */
    public static File getSidecarFile(File databaseFile) {
        return new File(databaseFile.getParentFile(), databaseFile.getName() + SIDECAR_EXTENSION);
    }

    /** Check whether a YubiKey is enrolled for the given database. */
    public static boolean isEnrolled(File databaseFile) {
        File sidecar = getSidecarFile(databaseFile);
        if (!sidecar.exists()) return false;
        long len = sidecar.length();
        return len == SIDECAR_V1_SIZE || len >= SIDECAR_V2_HEADER_SIZE;
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

    /** Generate a new random DB key for PASSWORDLESS / PASSWORD_OR_YUBIKEY modes. */
    public static byte[] generateDbKey() {
        byte[] key = new byte[DB_KEY_LENGTH];
        new SecureRandom().nextBytes(key);
        return key;
    }

    /**
     * Save v1 enrollment (PASSWORD_REQUIRED mode — backward compatible).
     */
    public static void saveEnrollment(File databaseFile, int slot,
                                      byte[] challenge, byte[] expectedResponse) throws IOException {
        saveEnrollmentV2(databaseFile, slot, challenge, expectedResponse,
                UnlockMode.PASSWORD_REQUIRED, null, null);
    }

    /**
     * Save v2 enrollment with mode and optional key-wrap blobs.
     *
     * @param databaseFile     The database file
     * @param slot             YubiKey slot (1 or 2)
     * @param challenge        The 32-byte challenge
     * @param expectedResponse The 20-byte expected HMAC-SHA1 response
     * @param mode             The unlock mode
     * @param ykWrappedKey     YubiKey-wrapped DB key blob (modes 2,3), or null
     * @param pwWrappedKey     Password-wrapped DB key blob (mode 3), or null
     */
    public static void saveEnrollmentV2(File databaseFile, int slot,
                                        byte[] challenge, byte[] expectedResponse,
                                        UnlockMode mode,
                                        byte[] ykWrappedKey, byte[] pwWrappedKey) throws IOException {
        if (challenge.length != CHALLENGE_LENGTH)
            throw new IllegalArgumentException("Challenge must be " + CHALLENGE_LENGTH + " bytes");
        if (expectedResponse.length != HMAC_RESPONSE_LENGTH)
            throw new IllegalArgumentException("Response must be " + HMAC_RESPONSE_LENGTH + " bytes");
        if (slot != 1 && slot != 2)
            throw new IllegalArgumentException("Slot must be 1 or 2");

        File sidecar = getSidecarFile(databaseFile);
        try (FileOutputStream fos = new FileOutputStream(sidecar)) {
            fos.write(MAGIC);

            if (mode == UnlockMode.PASSWORD_REQUIRED && ykWrappedKey == null && pwWrappedKey == null) {
                // Write v1 format for backward compatibility
                fos.write(FORMAT_VERSION_1);
            } else {
                // Write v2 format
                fos.write(FORMAT_VERSION_2);
            }

            fos.write((byte) slot);
            fos.write(challenge);
            fos.write(expectedResponse);

            if (mode != UnlockMode.PASSWORD_REQUIRED || ykWrappedKey != null || pwWrappedKey != null) {
                // V2 extension: mode byte + TLV blobs
                fos.write((byte) mode.code);

                if (ykWrappedKey != null) {
                    fos.write(BLOB_TAG_YK_WRAPPED_KEY);
                    fos.write((ykWrappedKey.length >> 8) & 0xFF);
                    fos.write(ykWrappedKey.length & 0xFF);
                    fos.write(ykWrappedKey);
                }
                if (pwWrappedKey != null) {
                    fos.write(BLOB_TAG_PW_WRAPPED_KEY);
                    fos.write((pwWrappedKey.length >> 8) & 0xFF);
                    fos.write(pwWrappedKey.length & 0xFF);
                    fos.write(pwWrappedKey);
                }
            }
            fos.flush();
        }
        Log.i(TAG, "YubiKey enrollment saved (slot " + slot + ", mode " + mode + ")");
    }

    /** Load the saved slot number. */
    public static int loadSlot(File databaseFile) {
        byte[] data = readSidecarRaw(databaseFile);
        if (data == null) return DEFAULT_SLOT;
        return data[MAGIC.length + 1] & 0xFF;
    }

    /** Load the 32-byte challenge, or null. */
    public static byte[] loadChallenge(File databaseFile) {
        byte[] data = readSidecarRaw(databaseFile);
        if (data == null) return null;
        byte[] challenge = new byte[CHALLENGE_LENGTH];
        System.arraycopy(data, MAGIC.length + 2, challenge, 0, CHALLENGE_LENGTH);
        return challenge;
    }

    /** Load the 20-byte expected response, or null. */
    public static byte[] loadExpectedResponse(File databaseFile) {
        byte[] data = readSidecarRaw(databaseFile);
        if (data == null) return null;
        byte[] response = new byte[HMAC_RESPONSE_LENGTH];
        System.arraycopy(data, MAGIC.length + 2 + CHALLENGE_LENGTH, response, 0, HMAC_RESPONSE_LENGTH);
        return response;
    }

    /** Load the unlock mode from the sidecar. V1 files return PASSWORD_REQUIRED. */
    public static UnlockMode loadMode(File databaseFile) {
        byte[] data = readSidecarRaw(databaseFile);
        if (data == null) return UnlockMode.PASSWORD_REQUIRED;
        int version = data[MAGIC.length] & 0xFF;
        if (version < 2 || data.length < SIDECAR_V2_HEADER_SIZE) return UnlockMode.PASSWORD_REQUIRED;
        return UnlockMode.fromCode(data[SIDECAR_V1_SIZE] & 0xFF);
    }

    /** Load a specific TLV blob from a v2 sidecar, or null. */
    public static byte[] loadBlob(File databaseFile, byte tag) {
        byte[] data = readSidecarRaw(databaseFile);
        if (data == null) return null;
        int version = data[MAGIC.length] & 0xFF;
        if (version < 2 || data.length < SIDECAR_V2_HEADER_SIZE) return null;

        // Parse TLV blobs starting after v2 header
        int offset = SIDECAR_V2_HEADER_SIZE;
        while (offset + 3 <= data.length) {
            byte blobTag = data[offset];
            int blobLen = ((data[offset + 1] & 0xFF) << 8) | (data[offset + 2] & 0xFF);
            offset += 3;
            if (offset + blobLen > data.length) break;
            if (blobTag == tag) {
                byte[] blob = new byte[blobLen];
                System.arraycopy(data, offset, blob, 0, blobLen);
                return blob;
            }
            offset += blobLen;
        }
        return null;
    }

    /** Load YubiKey-wrapped DB key blob, or null. */
    public static byte[] loadYkWrappedKey(File databaseFile) {
        return loadBlob(databaseFile, BLOB_TAG_YK_WRAPPED_KEY);
    }

    /** Load password-wrapped DB key blob, or null. */
    public static byte[] loadPwWrappedKey(File databaseFile) {
        return loadBlob(databaseFile, BLOB_TAG_PW_WRAPPED_KEY);
    }

    /** Read the entire sidecar file raw, validating magic only. */
    private static byte[] readSidecarRaw(File databaseFile) {
        File sidecar = getSidecarFile(databaseFile);
        if (!sidecar.exists()) return null;

        try (FileInputStream fis = new FileInputStream(sidecar)) {
            byte[] data = new byte[(int) sidecar.length()];
            if (fis.read(data) != data.length) return null;

            // Verify magic
            if (data.length < MAGIC.length + 1) return null;
            for (int i = 0; i < MAGIC.length; i++) {
                if (data[i] != MAGIC[i]) return null;
            }
            // Verify version is known
            int version = data[MAGIC.length] & 0xFF;
            if (version != FORMAT_VERSION_1 && version != FORMAT_VERSION_2) return null;

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
        Log.d(TAG, "Sending SELECT APDU (" + selectApdu.length + " bytes)");
        byte[] selectResponse = isoDep.transceive(selectApdu);
        Log.d(TAG, "SELECT response: " + selectResponse.length + " bytes, SW="
                + String.format("%04X", extractSW(selectResponse)));
        checkSW(selectResponse, "SELECT OTP applet");

        // Step 2: Send HMAC-SHA1 challenge
        byte slotP2 = (slot == 1) ? SLOT1_HMAC : SLOT2_HMAC;
        byte[] hmacApdu = buildHmacApdu(slotP2, challenge);
        Log.d(TAG, "Sending HMAC APDU for slot " + slot + " (" + hmacApdu.length + " bytes)");
        byte[] hmacResponse = isoDep.transceive(hmacApdu);
        Log.d(TAG, "HMAC response: " + hmacResponse.length + " bytes, SW="
                + String.format("%04X", extractSW(hmacResponse)));
        checkSW(hmacResponse, "HMAC-SHA1 challenge-response");

        // Extract the 20-byte HMAC result (response minus 2-byte status word)
        if (hmacResponse.length < HMAC_RESPONSE_LENGTH + 2) {
            throw new YubiKeyException(
                    "YubiKey slot " + slot + " did not return HMAC data (got " + hmacResponse.length
                    + " bytes). Is HMAC-SHA1 Challenge-Response configured in slot " + slot
                    + "? Use the YubiKey Manager desktop app to configure it.");
        }

        byte[] result = new byte[HMAC_RESPONSE_LENGTH];
        System.arraycopy(hmacResponse, 0, result, 0, HMAC_RESPONSE_LENGTH);

        Log.i(TAG, "HMAC-SHA1 challenge-response successful (slot " + slot + ")");
        return result;
    }

    /** Extract SW1-SW2 from an APDU response (last 2 bytes). */
    private static int extractSW(byte[] response) {
        if (response == null || response.length < 2) return -1;
        return ((response[response.length - 2] & 0xFF) << 8)
                | (response[response.length - 1] & 0xFF);
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
    //  USB HID challenge-response (YubiKey plugged in via USB-C/USB-A)
    // ═════════════════════════════════════════════════════════════════════

    /** Yubico USB vendor ID. */
    public static final int YUBICO_VENDOR_ID = 0x1050;

    /** YubiKey HID frame size. */
    private static final int HID_FRAME_SIZE = 64;

    /** Slot command bytes for USB HID protocol. */
    private static final byte USB_SLOT1_HMAC = 0x30;
    private static final byte USB_SLOT2_HMAC = 0x38;

    /** Status flags in HID response. */
    private static final int STATUS_FLAG_RESPONSE_PENDING = 0x40;

    /** USB timeout in milliseconds. */
    private static final int USB_TIMEOUT_MS = 10000;

    /**
     * Check if a USB device is a YubiKey.
     */
    public static boolean isYubiKey(UsbDevice device) {
        return device != null && device.getVendorId() == YUBICO_VENDOR_ID;
    }

    /**
     * Find a connected YubiKey USB device, or null.
     */
    public static UsbDevice findYubiKey(UsbManager usbManager) {
        if (usbManager == null) return null;
        for (UsbDevice device : usbManager.getDeviceList().values()) {
            if (isYubiKey(device)) return device;
        }
        return null;
    }

    /**
     * Perform HMAC-SHA1 challenge-response with a YubiKey over USB HID.
     *
     * <p>The YubiKey USB HID protocol uses 64-byte frames. We write the
     * challenge into a slot request frame and read back the HMAC response.
     *
     * @param connection An open USB device connection
     * @param device     The YubiKey USB device
     * @param slot       YubiKey slot (1 or 2)
     * @param challenge  The challenge bytes (up to 64 bytes, typically 32)
     * @return The 20-byte HMAC-SHA1 response
     * @throws IOException if USB communication fails
     * @throws YubiKeyException if the YubiKey returns an error
     */
    public static byte[] performChallengeResponseUsb(UsbDeviceConnection connection,
                                                      UsbDevice device, int slot,
                                                      byte[] challenge)
            throws IOException, YubiKeyException {

        // Find the HID interface and endpoints
        UsbInterface hidInterface = null;
        UsbEndpoint endpointIn = null;
        UsbEndpoint endpointOut = null;

        for (int i = 0; i < device.getInterfaceCount(); i++) {
            UsbInterface iface = device.getInterface(i);
            if (iface.getInterfaceClass() == UsbConstants.USB_CLASS_HID) {
                hidInterface = iface;
                for (int j = 0; j < iface.getEndpointCount(); j++) {
                    UsbEndpoint ep = iface.getEndpoint(j);
                    if (ep.getDirection() == UsbConstants.USB_DIR_IN) {
                        endpointIn = ep;
                    } else {
                        endpointOut = ep;
                    }
                }
                break;
            }
        }

        if (hidInterface == null || endpointIn == null) {
            throw new YubiKeyException("No HID interface found on YubiKey USB device");
        }

        if (!connection.claimInterface(hidInterface, true)) {
            throw new YubiKeyException("Failed to claim YubiKey USB HID interface");
        }

        try {
            // Build the challenge frame
            // YubiKey HID frame: [challenge_data(64)] + [slot_cmd(1)] + [challenge_len(1)] + padding
            // The frame structure for HMAC challenge:
            //   Bytes 0-63:  challenge data (padded to 64 bytes)
            //   Written as a series of HID reports
            byte slotCmd = (slot == 1) ? USB_SLOT1_HMAC : USB_SLOT2_HMAC;

            // Pad challenge to 64 bytes
            byte[] paddedChallenge = new byte[64];
            int challengeLen = Math.min(challenge.length, 64);
            System.arraycopy(challenge, 0, paddedChallenge, 0, challengeLen);

            // Build the 70-byte YubiKey frame:
            // [64 bytes payload] [1 byte slot] [2 bytes CRC] [3 bytes padding]
            byte[] frame = new byte[70];
            System.arraycopy(paddedChallenge, 0, frame, 0, 64);
            frame[64] = slotCmd;
            // CRC16 over first 66 bytes (payload + slot)
            int crc = crc16(frame, 65);
            frame[65] = (byte) (crc & 0xFF);
            frame[66] = (byte) ((crc >> 8) & 0xFF);

            // Send frame in HID reports (8 bytes per report, with 1-byte sequence prefix)
            // Each USB HID report: [seq_num] [8 bytes data]
            for (int seq = 0; seq < 10; seq++) {
                byte[] report = new byte[HID_FRAME_SIZE];
                report[7] = (byte) seq; // Sequence number at byte 7
                int offset = seq * 7;
                int remaining = Math.min(7, frame.length - offset);
                if (remaining > 0) {
                    System.arraycopy(frame, offset, report, 0, remaining);
                }

                if (endpointOut != null) {
                    int sent = connection.bulkTransfer(endpointOut, report, report.length, USB_TIMEOUT_MS);
                    if (sent < 0) {
                        throw new YubiKeyException("USB write failed at sequence " + seq);
                    }
                } else {
                    // Fall back to control transfer for keyboards without OUT endpoint
                    int sent = connection.controlTransfer(
                            0x21, // REQUEST_TYPE: class, interface, host-to-device
                            0x09, // SET_REPORT
                            0x0200, // HID report type OUTPUT, report ID 0
                            hidInterface.getId(),
                            report, report.length, USB_TIMEOUT_MS);
                    if (sent < 0) {
                        throw new YubiKeyException("USB control transfer failed at sequence " + seq);
                    }
                }
            }

            // Read response — poll until we get a valid response
            byte[] responseFrame = new byte[70];
            int responseOffset = 0;
            long startTime = System.currentTimeMillis();

            while (System.currentTimeMillis() - startTime < USB_TIMEOUT_MS) {
                byte[] readBuf = new byte[HID_FRAME_SIZE];
                int read = connection.bulkTransfer(endpointIn, readBuf, readBuf.length, 1000);
                if (read < 0) {
                    // Timeout on this read, try again
                    continue;
                }

                // Check status byte — byte index 7 is the sequence/status
                int seqNum = readBuf[7] & 0xFF;
                if (seqNum == 0xFF) {
                    // Status frame — check if response is pending
                    continue;
                }

                // Copy data bytes from this report into response frame
                int copyLen = Math.min(7, responseFrame.length - responseOffset);
                if (copyLen > 0) {
                    System.arraycopy(readBuf, 0, responseFrame, responseOffset, copyLen);
                    responseOffset += copyLen;
                }

                if (responseOffset >= 70) break;
            }

            if (responseOffset < 22) { // Need at least 20 bytes HMAC + 2 CRC
                throw new YubiKeyException("USB response too short: got " + responseOffset + " bytes");
            }

            // Extract the 20-byte HMAC result
            byte[] result = new byte[HMAC_RESPONSE_LENGTH];
            System.arraycopy(responseFrame, 0, result, 0, HMAC_RESPONSE_LENGTH);

            Log.i(TAG, "USB HMAC-SHA1 challenge-response successful (slot " + slot + ")");
            return result;

        } finally {
            connection.releaseInterface(hidInterface);
        }
    }

    /**
     * CRC-16 used by YubiKey HID protocol (CRC-16/ISO 13239).
     */
    private static int crc16(byte[] data, int length) {
        int crc = 0xFFFF;
        for (int i = 0; i < length; i++) {
            crc ^= (data[i] & 0xFF);
            for (int j = 0; j < 8; j++) {
                if ((crc & 1) != 0) {
                    crc = (crc >> 1) ^ 0x8408;
                } else {
                    crc >>= 1;
                }
            }
        }
        return crc;
    }


    // ═════════════════════════════════════════════════════════════════════
    //  HKDF + Key wrapping for PASSWORDLESS / PASSWORD_OR_YUBIKEY modes
    // ═════════════════════════════════════════════════════════════════════

    /**
     * HKDF-SHA256 extract-and-expand (RFC 5869).
     * Derives a 256-bit key from the YubiKey HMAC response.
     */
    public static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int outputLen) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            // Extract
            if (salt == null || salt.length == 0) salt = new byte[32];
            mac.init(new SecretKeySpec(salt, "HmacSHA256"));
            byte[] prk = mac.doFinal(ikm);
            // Expand
            int n = (outputLen + 31) / 32;
            byte[] okm = new byte[outputLen];
            byte[] t = new byte[0];
            int offset = 0;
            for (int i = 1; i <= n; i++) {
                mac.init(new SecretKeySpec(prk, "HmacSHA256"));
                mac.update(t);
                if (info != null) mac.update(info);
                mac.update((byte) i);
                t = mac.doFinal();
                int len = Math.min(32, outputLen - offset);
                System.arraycopy(t, 0, okm, offset, len);
                offset += len;
            }
            Arrays.fill(prk, (byte) 0);
            return okm;
        } catch (Exception e) {
            throw new RuntimeException("HKDF-SHA256 failed", e);
        }
    }

    /**
     * Wrap (encrypt) a DB key using a YubiKey HMAC response via HKDF + AES-GCM.
     * @return blob: salt(16) + iv(12) + ciphertext+tag
     */
    public static byte[] wrapDbKeyWithYubiKey(byte[] dbKey, byte[] hmacResponse) throws Exception {
        byte[] salt = new byte[WRAP_SALT_LENGTH];
        new SecureRandom().nextBytes(salt);
        byte[] wrappingKey = hkdfSha256(hmacResponse, salt, HKDF_INFO, 32);

        byte[] iv = new byte[WRAP_IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(wrappingKey, "AES"),
                new GCMParameterSpec(WRAP_TAG_BITS, iv));
        byte[] ciphertext = cipher.doFinal(dbKey);
        Arrays.fill(wrappingKey, (byte) 0);

        // Assemble blob: salt + iv + ciphertext
        byte[] blob = new byte[salt.length + iv.length + ciphertext.length];
        System.arraycopy(salt, 0, blob, 0, salt.length);
        System.arraycopy(iv, 0, blob, salt.length, iv.length);
        System.arraycopy(ciphertext, 0, blob, salt.length + iv.length, ciphertext.length);
        return blob;
    }

    /**
     * Unwrap (decrypt) a DB key using a YubiKey HMAC response.
     * @param blob  The blob from wrapDbKeyWithYubiKey
     * @return The 32-byte DB key, or null on failure
     */
    public static byte[] unwrapDbKeyWithYubiKey(byte[] blob, byte[] hmacResponse) {
        try {
            if (blob.length < WRAP_SALT_LENGTH + WRAP_IV_LENGTH + 1) return null;

            byte[] salt = new byte[WRAP_SALT_LENGTH];
            byte[] iv = new byte[WRAP_IV_LENGTH];
            System.arraycopy(blob, 0, salt, 0, WRAP_SALT_LENGTH);
            System.arraycopy(blob, WRAP_SALT_LENGTH, iv, 0, WRAP_IV_LENGTH);
            byte[] ciphertext = new byte[blob.length - WRAP_SALT_LENGTH - WRAP_IV_LENGTH];
            System.arraycopy(blob, WRAP_SALT_LENGTH + WRAP_IV_LENGTH, ciphertext, 0, ciphertext.length);

            byte[] wrappingKey = hkdfSha256(hmacResponse, salt, HKDF_INFO, 32);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(wrappingKey, "AES"),
                    new GCMParameterSpec(WRAP_TAG_BITS, iv));
            byte[] dbKey = cipher.doFinal(ciphertext);
            Arrays.fill(wrappingKey, (byte) 0);
            return dbKey;
        } catch (Exception e) {
            Log.e(TAG, "Failed to unwrap DB key with YubiKey", e);
            return null;
        }
    }

    /**
     * Wrap (encrypt) a DB key using a password via PBKDF2 + AES-GCM.
     * @return blob: salt(16) + iv(12) + ciphertext+tag
     */
    public static byte[] wrapDbKeyWithPassword(byte[] dbKey, char[] password) throws Exception {
        byte[] salt = new byte[WRAP_SALT_LENGTH];
        new SecureRandom().nextBytes(salt);

        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_WRAP_ITERATIONS, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();

        byte[] iv = new byte[WRAP_IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"),
                new GCMParameterSpec(WRAP_TAG_BITS, iv));
        byte[] ciphertext = cipher.doFinal(dbKey);
        Arrays.fill(keyBytes, (byte) 0);

        byte[] blob = new byte[salt.length + iv.length + ciphertext.length];
        System.arraycopy(salt, 0, blob, 0, salt.length);
        System.arraycopy(iv, 0, blob, salt.length, iv.length);
        System.arraycopy(ciphertext, 0, blob, salt.length + iv.length, ciphertext.length);
        return blob;
    }

    /**
     * Unwrap (decrypt) a DB key using a password.
     * @return The 32-byte DB key, or null on failure
     */
    public static byte[] unwrapDbKeyWithPassword(byte[] blob, char[] password) {
        try {
            if (blob.length < WRAP_SALT_LENGTH + WRAP_IV_LENGTH + 1) return null;

            byte[] salt = new byte[WRAP_SALT_LENGTH];
            byte[] iv = new byte[WRAP_IV_LENGTH];
            System.arraycopy(blob, 0, salt, 0, WRAP_SALT_LENGTH);
            System.arraycopy(blob, WRAP_SALT_LENGTH, iv, 0, WRAP_IV_LENGTH);
            byte[] ciphertext = new byte[blob.length - WRAP_SALT_LENGTH - WRAP_IV_LENGTH];
            System.arraycopy(blob, WRAP_SALT_LENGTH + WRAP_IV_LENGTH, ciphertext, 0, ciphertext.length);

            PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_WRAP_ITERATIONS, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"),
                    new GCMParameterSpec(WRAP_TAG_BITS, iv));
            byte[] dbKey = cipher.doFinal(ciphertext);
            Arrays.fill(keyBytes, (byte) 0);
            return dbKey;
        } catch (Exception e) {
            Log.e(TAG, "Failed to unwrap DB key with password", e);
            return null;
        }
    }

    /**
     * Convert a raw DB key to a char[] suitable for PasswordDatabase/PBKDF2.
     */
    public static char[] dbKeyToPassword(byte[] dbKey) {
        return Base64.encodeToString(dbKey, Base64.NO_WRAP | Base64.NO_PADDING).toCharArray();
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
     * Save a recovery blob protecting the HMAC response (mode 1: PASSWORD_REQUIRED).
     * Key = PBKDF2(password + recovery_code).
     */
    public static void saveRecoveryBlob(File databaseFile, char[] password,
                                        String recoveryCode, byte[] hmacResponse) throws Exception {
        saveRecoveryBlobInternal(databaseFile, password, recoveryCode, hmacResponse);
    }

    /**
     * Save a recovery blob protecting a raw DB key (modes 2, 3).
     * Key = PBKDF2(recovery_code) — no password component needed since the
     * DB key is the secret, not tied to any password.
     */
    public static void saveRecoveryBlobForDbKey(File databaseFile,
                                                String recoveryCode, byte[] dbKey) throws Exception {
        saveRecoveryBlobInternal(databaseFile, null, recoveryCode, dbKey);
    }

    private static void saveRecoveryBlobInternal(File databaseFile, char[] password,
                                                  String recoveryCode, byte[] secret) throws Exception {
        String normalized = normalizeRecoveryCode(recoveryCode);

        // Derive encryption key from password + recovery code (or just recovery code)
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        char[] keyInput = (password != null)
                ? combineForRecovery(password, normalized)
                : normalized.toCharArray();
        PBEKeySpec spec = new PBEKeySpec(keyInput, salt, PBKDF2_RECOVERY_ITERATIONS, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        Arrays.fill(keyInput, '\0');
        Arrays.fill(keyBytes, (byte) 0);

        // Encrypt the secret with AES-GCM
        byte[] iv = new byte[AES_GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(AES_GCM_TAG_BITS, iv));
        byte[] ciphertext = cipher.doFinal(secret);

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
     * Decrypt the recovery blob. Tries password+code first, then code-only.
     *
     * @return The protected secret (HMAC response or DB key), or null on failure
     */
    public static byte[] decryptRecoveryBlob(File databaseFile, char[] password,
                                             String recoveryCode) {
        // Try with password+code first (mode 1)
        byte[] result = decryptRecoveryBlobWithKey(databaseFile,
                combineForRecovery(password, normalizeRecoveryCode(recoveryCode)));
        if (result != null) return result;

        // Try code-only (modes 2, 3)
        return decryptRecoveryBlobWithKey(databaseFile,
                normalizeRecoveryCode(recoveryCode).toCharArray());
    }

    /**
     * Decrypt recovery blob using code only (no password). For modes 2/3.
     */
    public static byte[] decryptRecoveryBlobCodeOnly(File databaseFile, String recoveryCode) {
        return decryptRecoveryBlobWithKey(databaseFile,
                normalizeRecoveryCode(recoveryCode).toCharArray());
    }

    private static byte[] decryptRecoveryBlobWithKey(File databaseFile, char[] keyInput) {
        File recoveryFile = getRecoveryFile(databaseFile);
        if (!recoveryFile.exists()) return null;

        try (FileInputStream fis = new FileInputStream(recoveryFile)) {
            byte[] magic = new byte[RECOVERY_MAGIC.length];
            if (fis.read(magic) != magic.length) return null;
            if (!Arrays.equals(magic, RECOVERY_MAGIC)) return null;

            int version = fis.read();
            if (version != RECOVERY_VERSION) return null;

            byte[] salt = new byte[16];
            if (fis.read(salt) != salt.length) return null;

            byte[] iv = new byte[AES_GCM_IV_LENGTH];
            if (fis.read(iv) != iv.length) return null;

            byte[] ciphertext = new byte[fis.available()];
            if (fis.read(ciphertext) != ciphertext.length) return null;

            // Derive decryption key
            PBEKeySpec spec = new PBEKeySpec(keyInput, salt, PBKDF2_RECOVERY_ITERATIONS, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();
            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
            Arrays.fill(keyInput, '\0');
            Arrays.fill(keyBytes, (byte) 0);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(AES_GCM_TAG_BITS, iv));
            return cipher.doFinal(ciphertext);

        } catch (Exception e) {
            Log.d(TAG, "Recovery blob decryption attempt failed", e);
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

