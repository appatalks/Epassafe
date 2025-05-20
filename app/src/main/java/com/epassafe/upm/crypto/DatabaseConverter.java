/*
 * Epassafe Password Manager
 * Copyright (c) 2010-2025
 *
 * This file is part of Epassafe Password Manager.
 *
 * Epassafe Password Manager is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Epassafe Password Manager is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 */
package com.epassafe.upm.crypto;

import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

import com.epassafe.upm.database.AccountInformation;
import com.epassafe.upm.database.DatabaseHeader;
import com.epassafe.upm.database.DatabaseOptions;
import com.epassafe.upm.database.ProblemReadingDatabaseFile;
import com.epassafe.upm.database.Revision;
import com.epassafe.upm.util.Util;

/**
 * This utility facilitates migration from older encryption methods to the modern
 * authenticated encryption.
 */
public class DatabaseConverter {

    private static final String TAG = "DatabaseConverter";
    private static final String FILE_HEADER = "UPM";

    /**
     * Convert an existing database to use the modern encryption
     * @param databaseFile The database file to convert
     * @param password The master password for the database
     * @param useChaCha True to use ChaCha20-Poly1305, false to use AES-GCM
     * @return The converted database contents
     */
    public static byte[] convertDatabase(File databaseFile, char[] password, boolean useChaCha)
            throws IOException, GeneralSecurityException, ProblemReadingDatabaseFile, InvalidPasswordException {

        Log.i(TAG, "Converting database to modern format: " + databaseFile.getName());

        // First load and decrypt the existing database
        byte[] fullDatabase = Util.getBytesFromFile(databaseFile);

        // Variables to hold decrypted data and metadata
        ByteArrayInputStream is = null;
        Charset charset = StandardCharsets.UTF_8;
        Revision revision = null;
        DatabaseOptions dbOptions = null;
        byte[] decryptedBytes = null;

        // Check if this is a modern format (v2+) database
        byte[] header = new byte[FILE_HEADER.getBytes().length];
        System.arraycopy(fullDatabase, 0, header, 0, header.length);

        if (Arrays.equals(header, FILE_HEADER.getBytes())) {
            Log.i(TAG, "Converting modern format database (v2+)");

            // Calculate the positions of each item in the file
            int dbVersionPos = header.length;
            int saltPos = dbVersionPos + 1;
            int encryptedBytesPos = saltPos + EncryptionService.SALT_LENGTH;

            byte dbVersion = fullDatabase[dbVersionPos];

            byte[] salt = new byte[EncryptionService.SALT_LENGTH];
            System.arraycopy(fullDatabase, saltPos, salt, 0, EncryptionService.SALT_LENGTH);

            int encryptedBytesLength = fullDatabase.length - encryptedBytesPos;
            byte[] encryptedBytes = new byte[encryptedBytesLength];
            System.arraycopy(fullDatabase, encryptedBytesPos, encryptedBytes, 0, encryptedBytesLength);

            // From version 3 onwards Strings in AccountInformation are encoded using UTF-8.
            if (dbVersion < 3) {
                charset = Util.defaultCharset();
            }

            // Decrypt with existing method
            SecretKey secretKey = EncryptionService.createSecretKey(password);
            EncryptionService encryptionService = new EncryptionService(secretKey, salt);
            decryptedBytes = encryptionService.decrypt(encryptedBytes);

            // Parse the decrypted data
            is = new ByteArrayInputStream(decryptedBytes);
            revision = new Revision(is);
            dbOptions = new DatabaseOptions(is);

        } else {
            // Legacy database (pre v2)
            Log.i(TAG, "Converting legacy format database (pre v2)");

            byte[] salt = new byte[EncryptionService.SALT_LENGTH];
            System.arraycopy(fullDatabase, 0, salt, 0, EncryptionService.SALT_LENGTH);

            int encryptedBytesLength = fullDatabase.length - EncryptionService.SALT_LENGTH;
            byte[] encryptedBytes = new byte[encryptedBytesLength];
            System.arraycopy(fullDatabase, EncryptionService.SALT_LENGTH, encryptedBytes, 0, encryptedBytesLength);

            // Try to decrypt using existing methods
            SecretKey secretKey = EncryptionService.createSecretKey(password);
            try {
                // First try AES
                decryptedBytes = DESDecryptionService.decryptAES(secretKey, salt, encryptedBytes);
            } catch (Exception e) {
                // Fall back to legacy DES
                decryptedBytes = DESDecryptionService.decrypt(secretKey, salt, encryptedBytes);
            }

            // Parse the decrypted data
            is = new ByteArrayInputStream(decryptedBytes);
            DatabaseHeader dh = new DatabaseHeader(is);

            // Check database version
            if (dh.getVersion().equals("1.1.0")) {
                revision = new Revision(is);
                dbOptions = new DatabaseOptions(is);
            } else if (dh.getVersion().equals("1.0.0")) {
                revision = new Revision();
                dbOptions = new DatabaseOptions();
            } else {
                throw new ProblemReadingDatabaseFile("Unknown database version: " + dh.getVersion());
            }
        }

        // At this point we have:
        // 1. Decrypted database bytes
        // 2. Database revision and options
        // 3. An input stream positioned at the accounts data

        // Re-encrypt with the modern encryption service

        // First collect all accounts from the input stream
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        // Write revision and options
        revision.increment(); // Increment revision since we're converting
        revision.flatPack(baos);
        dbOptions.flatPack(baos);

        // Copy account data
        try {
            while (true) {
                AccountInformation ai = new AccountInformation(is, charset);
                ai.flatPack(baos);
            }
        } catch (EOFException e) {
            // Expected exception when we reach end of file
        }

        // Close streams
        if (is != null) {
            is.close();
        }
        baos.close();

        // Get the account data to encrypt
        byte[] dataToEncrypt = baos.toByteArray();

        // Create a new modern encryption service
        ModernEncryptionService modernEncryption = new ModernEncryptionService(password);
        modernEncryption.setAlgorithm(useChaCha);
        byte[] encryptedData = modernEncryption.encrypt(dataToEncrypt);

        // Format the database header
        ByteArrayOutputStream header_os = new ByteArrayOutputStream();
        // Use a new magic header to identify modern encryption
        header_os.write("UPM_MODERN".getBytes());
        // Write format version
        header_os.write(ModernEncryptionService.FORMAT_VERSION);
        // Write salt
        header_os.write(modernEncryption.getSalt());
        // Write encrypted data
        header_os.write(encryptedData);
        header_os.close();

        Log.i(TAG, "Database conversion completed successfully");

        return header_os.toByteArray();
    }

    /**
     * Detects if a database file is using the modern encryption format
     * @param file The database file to check
     * @return true if it's a modern format, false otherwise
     */
    public static boolean isModernFormat(File file) throws IOException {
        if (!file.exists() || file.length() < "UPM_MODERN".length()) {
            return false;
        }

        byte[] header = new byte["UPM_MODERN".getBytes().length];
        byte[] fileHeader = Util.getBytesFromFile(file, header.length);

        return Arrays.equals(fileHeader, "UPM_MODERN".getBytes());
    }

    /**
     * Detect which algorithm (AES-GCM or ChaCha20-Poly1305) was used in a modern format database
     * @param encryptedData The encrypted data block (not the whole file)
     * @return "AES-GCM" or "ChaCha20-Poly1305"
     */
    public static String detectAlgorithm(byte[] encryptedData) {
        if (encryptedData == null || encryptedData.length == 0) {
            return "Unknown";
        }

        // The algorithm ID is stored as the first byte
        byte algorithmId = encryptedData[0];

        if (algorithmId == ModernEncryptionService.ALG_AES_GCM) {
            return "AES-GCM";
        } else if (algorithmId == ModernEncryptionService.ALG_CHACHA20_POLY1305) {
            return "ChaCha20-Poly1305";
        } else {
            return "Unknown";
        }
    }
}
