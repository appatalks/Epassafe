/*
 * Universal Password Manager
 \* Copyright (c) 2010-2025
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
package com.epassafe.upm.database;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import android.util.Log;

import com.epassafe.upm.crypto.DESDecryptionService;
import com.epassafe.upm.crypto.DatabaseConverter;
import com.epassafe.upm.crypto.EncryptionService;
import com.epassafe.upm.crypto.InvalidPasswordException;
import com.epassafe.upm.crypto.ModernEncryptionService;
import com.epassafe.upm.util.Util;


/**
 * This class represents the main interface to a password database.
 * All interaction with the database file is done using this class.
 * 
 * Database versions and formats. The items between [] brackets are encrypted.
 *   4      >> UPM_MODERN FORMAT_VERSION SALT [ENCRYPTED DATA WITH ALGORITHM IDENTIFIER]
 *        (all strings are encoded using UTF-8, Argon2id KDF, AES-GCM or ChaCha20-Poly1305)
 *   3      >> MAGIC_NUMBER DB_VERSION SALT [DB_REVISION DB_OPTIONS ACCOUNTS]
 *        (all strings are encoded using UTF-8)
 *   2      >> MAGIC_NUMBER DB_VERSION SALT [DB_REVISION DB_OPTIONS ACCOUNTS]
 *   1.1.0  >> SALT [DB_HEADER DB_REVISION DB_OPTIONS ACCOUNTS]
 *   1.0.0  >> SALT [DB_HEADER ACCOUNTS]
 *
 *   DB_VERSION = The structural version of the database
 *   SALT = The salt used to mix with the user password to create the key
 *   DB_HEADER = Was used to store the structural version of the database (pre version 2)
 *   DB_OPTIONS = Options relating to the database
 *   ACCOUNTS = The account information
 */
public class PasswordDatabase {

    private static final String TAG = "PasswordDatabase";
    private static final int DB_VERSION = 3;
    private static final String FILE_HEADER = "UPM";
    private static final String MODERN_FILE_HEADER = "UPM_MODERN";

    private File databaseFile;
    private Revision revision;
    private DatabaseOptions dbOptions;
    private HashMap<String, AccountInformation> accounts;
    private EncryptionService encryptionService;
    private ModernEncryptionService modernEncryptionService;
    private boolean isUsingModernEncryption = false;
    private boolean preferChaCha20 = false;


    public PasswordDatabase(File dbFile, SecretKey secretKey) throws IOException, GeneralSecurityException, ProblemReadingDatabaseFile, InvalidPasswordException {
        databaseFile = dbFile;
        load(secretKey);
    }


    public PasswordDatabase(File dbFile, char[] password) throws IOException, GeneralSecurityException, ProblemReadingDatabaseFile, InvalidPasswordException {
        this(dbFile, password, false);
    }


    public PasswordDatabase(File dbFile, char[] password, boolean overwrite) throws IOException, GeneralSecurityException, ProblemReadingDatabaseFile, InvalidPasswordException {
        databaseFile = dbFile;
        //Either create a new file (if it exists and overwrite == true OR it doesn't exist) or open the existing file
        if ((databaseFile.exists() && overwrite == true) || !databaseFile.exists()) {
            databaseFile.delete();
            databaseFile.createNewFile();
            revision = new Revision();
            dbOptions = new DatabaseOptions();
            accounts = new HashMap<String, AccountInformation>();

            // Use modern encryption by default for new databases
            try {
                isUsingModernEncryption = true;
                modernEncryptionService = new ModernEncryptionService(password);
                // Can set algorithm preference here (AES-GCM is default)
                // modernEncryptionService.setAlgorithm(true); // true = ChaCha20-Poly1305
            } catch (Exception e) {
                // Fall back to legacy encryption if modern fails
                Log.w(TAG, "Modern encryption initialization failed, falling back to legacy encryption", e);
                isUsingModernEncryption = false;
                encryptionService = new EncryptionService(password);
            }
        } else {
            // Store the original password for modern decryption
            // then also create a SecretKey for legacy formats
            load(password, EncryptionService.createSecretKey(password));
        }
    }


    public void changePassword(char[] password) throws GeneralSecurityException {
        if (isUsingModernEncryption) {
            try {
                modernEncryptionService = new ModernEncryptionService(password);
                // Preserve the algorithm choice (AES-GCM vs ChaCha20-Poly1305)
                modernEncryptionService.setAlgorithm(preferChaCha20);
            } catch (NoSuchAlgorithmException e) {
                throw new GeneralSecurityException("Failed to change password with modern encryption", e);
            }
        } else {
            encryptionService = new EncryptionService(password);
        }
    }

    /**
     * Upgrade to modern encryption. This will use the modern encryption
     * format with Argon2id and authenticated encryption.
     * @param password The current master password
     * @param useChaCha Whether to use ChaCha20-Poly1305 instead of AES-GCM
     * @throws GeneralSecurityException
     */
    public void upgradeToModernEncryption(char[] password, boolean useChaCha) throws GeneralSecurityException {
        if (isUsingModernEncryption) {
            // Already using modern encryption, just update algorithm choice if needed
            if (preferChaCha20 != useChaCha) {
                preferChaCha20 = useChaCha;
                modernEncryptionService.setAlgorithm(preferChaCha20);
            }
            return;
        }

        try {
            modernEncryptionService = new ModernEncryptionService(password);
            modernEncryptionService.setAlgorithm(useChaCha);
            preferChaCha20 = useChaCha;
            isUsingModernEncryption = true;
        } catch (NoSuchAlgorithmException e) {
            throw new GeneralSecurityException("Failed to upgrade to modern encryption", e);
        }
    }


    private void load(SecretKey secretKey) throws IOException, GeneralSecurityException, ProblemReadingDatabaseFile, InvalidPasswordException {
        //Read in the encrypted bytes
        byte[] fullDatabase = Util.getBytesFromFile(databaseFile);

        // Check the database has minimum length
        if (fullDatabase.length < EncryptionService.SALT_LENGTH) {
            throw new ProblemReadingDatabaseFile("This file doesn't appear to be a UPM password database");
        }

        ByteArrayInputStream is = null;
        Charset charset = Charset.forName("UTF-8");

        // Check for modern format first (UPM_MODERN header)
        byte[] modernHeader = new byte[MODERN_FILE_HEADER.getBytes().length];
        if (fullDatabase.length >= modernHeader.length) {
            System.arraycopy(fullDatabase, 0, modernHeader, 0, modernHeader.length);

            if (Arrays.equals(modernHeader, MODERN_FILE_HEADER.getBytes())) {
                Log.i(TAG, "Loading modern format database");
                isUsingModernEncryption = true;

                // Calculate positions of items in the file
                int formatVersionPos = modernHeader.length;
                int saltPos = formatVersionPos + 1;
                int encryptedBytesPos = saltPos + ModernEncryptionService.SALT_LENGTH;

                // Get format version
                byte formatVersion = fullDatabase[formatVersionPos];

                if (formatVersion == ModernEncryptionService.FORMAT_VERSION) {
                    // Extract salt
                    byte[] salt = new byte[ModernEncryptionService.SALT_LENGTH];
                    System.arraycopy(fullDatabase, saltPos, salt, 0, ModernEncryptionService.SALT_LENGTH);

                    // Extract encrypted data
                    int encryptedBytesLength = fullDatabase.length - encryptedBytesPos;
                    byte[] encryptedBytes = new byte[encryptedBytesLength];
                    System.arraycopy(fullDatabase, encryptedBytesPos, encryptedBytes, 0, encryptedBytesLength);

                    // Detect which algorithm was used (AES-GCM or ChaCha20-Poly1305)
                    if (encryptedBytes.length > 0) {
                        preferChaCha20 = (encryptedBytes[0] == ModernEncryptionService.ALG_CHACHA20_POLY1305);
                    }

                    // Attempt to decrypt the database
                    try {
                        // Extract password from SecretKey - FIXED: removed incorrect initialization
                        char[] passwordChars = null;

                        // Check if we're using a password directly or a SecretKey
                        if (secretKey != null) {
                            // Convert the key to a char array for modern encryption
                            // This is a temporary measure - not cryptographically ideal but allows backward compatibility
                            String keyStr = new String(secretKey.getEncoded());
                            passwordChars = keyStr.toCharArray();
                        }

                        // Initialize the modern encryption service with the password
                        modernEncryptionService = new ModernEncryptionService(passwordChars, salt);

                        // Apply the detected algorithm preference to the encryption service
                        if (preferChaCha20) {
                            modernEncryptionService.setAlgorithm(true);
                        }

                        // Clear password from memory after use
                        if (passwordChars != null) {
                            Arrays.fill(passwordChars, '\0');
                        }

                        byte[] decryptedBytes = modernEncryptionService.decrypt(encryptedBytes);

                        // Load the decrypted database contents
                        is = new ByteArrayInputStream(decryptedBytes);
                        revision = new Revision(is);
                        dbOptions = new DatabaseOptions(is);
                    } catch (Exception e) {
                        Log.e(TAG, "Failed to decrypt database with modern encryption", e);
                        throw new InvalidPasswordException("Failed to decrypt the database. Either the password is incorrect or the database is corrupted.");
                    }
                } else {
                    throw new ProblemReadingDatabaseFile("Unsupported modern database format version: " + formatVersion);
                }
            }
        }

        // If we didn't load as modern format, try legacy formats
        if (!isUsingModernEncryption) {
            // Check for UPM standard format
            byte[] legacyHeader = new byte[FILE_HEADER.getBytes().length];
            System.arraycopy(fullDatabase, 0, legacyHeader, 0, legacyHeader.length);

            if (Arrays.equals(legacyHeader, FILE_HEADER.getBytes())) {
                Log.i(TAG, "Loading legacy format database (v2+)");

                // Calculate the positions of each item in the file
                int dbVersionPos      = legacyHeader.length;
                int saltPos           = dbVersionPos + 1;
                int encryptedBytesPos = saltPos + EncryptionService.SALT_LENGTH;

                // Get the database version
                byte dbVersion = fullDatabase[dbVersionPos];

                if (dbVersion == 2 || dbVersion == 3) {
                    byte[] salt = new byte[EncryptionService.SALT_LENGTH];
                    System.arraycopy(fullDatabase, saltPos, salt, 0, EncryptionService.SALT_LENGTH);
                    int encryptedBytesLength = fullDatabase.length - encryptedBytesPos;
                    byte[] encryptedBytes = new byte[encryptedBytesLength];
                    System.arraycopy(fullDatabase, encryptedBytesPos, encryptedBytes, 0, encryptedBytesLength);

                    // From version 3 onwards Strings in AccountInformation are
                    // encoded using UTF-8. To ensure we can still open older dbs
                    // we default back to the then character set, the system default
                    if (dbVersion < 3) {
                        charset = Util.defaultCharset();
                    }

                    //Attempt to decrypt the database information
                    encryptionService = new EncryptionService(secretKey, salt);
                    byte[] decryptedBytes = encryptionService.decrypt(encryptedBytes);

                    //If we've got here then the database was successfully decrypted
                    is = new ByteArrayInputStream(decryptedBytes);
                    revision = new Revision(is);
                    dbOptions = new DatabaseOptions(is);
                } else {
                    throw new ProblemReadingDatabaseFile("Don't know how to handle database version [" + dbVersion + "]");
                }
            } else {
                // Try oldest format (pre v2)
                Log.i(TAG, "Loading ancient format database (pre v2)");

                // Check the database is a minimum length
                if (fullDatabase.length < EncryptionService.SALT_LENGTH) {
                    throw new ProblemReadingDatabaseFile("This file doesn't appear to be a UPM password database");
                }

                //Split up the salt and encrypted bytes
                byte[] salt = new byte[EncryptionService.SALT_LENGTH];
                System.arraycopy(fullDatabase, 0, salt, 0, EncryptionService.SALT_LENGTH);
                int encryptedBytesLength = fullDatabase.length - EncryptionService.SALT_LENGTH;
                byte[] encryptedBytes = new byte[encryptedBytesLength];
                System.arraycopy(fullDatabase, EncryptionService.SALT_LENGTH, encryptedBytes, 0, encryptedBytesLength);

                byte[] decryptedBytes = null;
                try {
                    // First try to decrypt using AES (in case it was encrypted with the modern algorithm)
                    try {
                        decryptedBytes = DESDecryptionService.decryptAES(secretKey, salt, encryptedBytes);
                    } catch (Exception e) {
                        // If AES decryption fails, fall back to legacy DES decryption
                        decryptedBytes = DESDecryptionService.decrypt(secretKey, salt, encryptedBytes);
                    }
                } catch (IllegalBlockSizeException e) {
                    throw new ProblemReadingDatabaseFile("Either your password is incorrect or this file isn't a UPM password database");
                }

                // Create the encryption for use later in the save() method
                // Always use the more secure AES encryption for future saves
                encryptionService = new EncryptionService(secretKey, salt);

                //We'll get to here if the password was correct so load up the decryped bytes
                is = new ByteArrayInputStream(decryptedBytes);
                DatabaseHeader dh = new DatabaseHeader(is);

                // At this point we'll check to see what version the database is and load it accordingly
                if (dh.getVersion().equals("1.1.0")) {
                    // Version 1.1.0 introduced a revision number & database options so read that in now
                    revision = new Revision(is);
                    dbOptions = new DatabaseOptions(is);
                } else if (dh.getVersion().equals("1.0.0")) {
                    revision = new Revision();
                    dbOptions = new DatabaseOptions();
                } else {
                    throw new ProblemReadingDatabaseFile("Don't know how to handle database version [" + dh.getVersion() + "]");
                }
            }
        }
        
        // Read the remainder of the database in now
        accounts = new HashMap<String, AccountInformation>();
        try {
            while (true) { //keep loading accounts until an EOFException is thrown
                AccountInformation ai = new AccountInformation(is, charset);
                addAccount(ai);
            }
        } catch (EOFException e) {
            //just means we hit eof
        }
        is.close();
    }

    /**
     * Load a database with both original password and SecretKey for
     * proper handling of different encryption formats
     */
    private void load(char[] password, SecretKey secretKey) throws IOException, GeneralSecurityException, ProblemReadingDatabaseFile, InvalidPasswordException {
        //Read in the encrypted bytes
        byte[] fullDatabase = Util.getBytesFromFile(databaseFile);

        // Check the database has minimum length
        if (fullDatabase.length < EncryptionService.SALT_LENGTH) {
            throw new ProblemReadingDatabaseFile("This file doesn't appear to be a UPM password database");
        }

        ByteArrayInputStream is = null;
        Charset charset = Charset.forName("UTF-8");

        // Check for modern format first (UPM_MODERN header)
        byte[] modernHeader = new byte[MODERN_FILE_HEADER.getBytes().length];
        if (fullDatabase.length >= modernHeader.length) {
            System.arraycopy(fullDatabase, 0, modernHeader, 0, modernHeader.length);

            if (Arrays.equals(modernHeader, MODERN_FILE_HEADER.getBytes())) {
                Log.i(TAG, "Loading modern format database using password");
                isUsingModernEncryption = true;

                // Calculate positions of items in the file
                int formatVersionPos = modernHeader.length;
                int saltPos = formatVersionPos + 1;
                int encryptedBytesPos = saltPos + ModernEncryptionService.SALT_LENGTH;

                // Get format version
                byte formatVersion = fullDatabase[formatVersionPos];

                if (formatVersion == ModernEncryptionService.FORMAT_VERSION) {
                    // Extract salt
                    byte[] salt = new byte[ModernEncryptionService.SALT_LENGTH];
                    System.arraycopy(fullDatabase, saltPos, salt, 0, ModernEncryptionService.SALT_LENGTH);

                    // Extract encrypted data
                    int encryptedBytesLength = fullDatabase.length - encryptedBytesPos;
                    byte[] encryptedBytes = new byte[encryptedBytesLength];
                    System.arraycopy(fullDatabase, encryptedBytesPos, encryptedBytes, 0, encryptedBytesLength);

                    // Detect which algorithm was used (AES-GCM or ChaCha20-Poly1305)
                    if (encryptedBytes.length > 0) {
                        preferChaCha20 = (encryptedBytes[0] == ModernEncryptionService.ALG_CHACHA20_POLY1305);
                    }

                    // Attempt to decrypt the database using the original password chars
                    try {
                        Log.d(TAG, "Initializing modern encryption with original password");
                        // Use the original password for modern encryption
                        modernEncryptionService = new ModernEncryptionService(password, salt);

                        byte[] decryptedBytes = modernEncryptionService.decrypt(encryptedBytes);

                        // Load the decrypted database contents
                        is = new ByteArrayInputStream(decryptedBytes);
                        revision = new Revision(is);
                        dbOptions = new DatabaseOptions(is);
                    } catch (Exception e) {
                        Log.e(TAG, "Failed to decrypt database with modern encryption", e);
                        throw new InvalidPasswordException("Failed to decrypt the database. Either the password is incorrect or the database is corrupted.");
                    }
                } else {
                    throw new ProblemReadingDatabaseFile("Unsupported modern database format version: " + formatVersion);
                }
            }
        }

        // If we didn't load as modern format, try legacy formats with the SecretKey
        if (!isUsingModernEncryption) {
            load(secretKey);
        }
        else {
            // We've already loaded account data in the modern decryption path, so just read accounts
            accounts = new HashMap<String, AccountInformation>();
            try {
                while (true) { //keep loading accounts until an EOFException is thrown
                    AccountInformation ai = new AccountInformation(is, charset);
                    addAccount(ai);
                }
            } catch (EOFException e) {
                //just means we hit eof
            }
            is.close();
        }
    }


    public void addAccount(AccountInformation ai) {
        accounts.put(ai.getAccountName(), ai);
    }
    

    public void deleteAccount(String accountName) {
        accounts.remove(accountName);
    }

    
    public AccountInformation getAccount(String name) {
        return accounts.get(name);
    }
    
    
    public void save() throws IOException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchProviderException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        
        // Flatpack the database revision and options
        revision.increment();
        revision.flatPack(os);
        dbOptions.flatPack(os);

        // Flatpack the accounts
        Iterator<AccountInformation> it = accounts.values().iterator();
        while (it.hasNext()) {
            AccountInformation ai = it.next();
            ai.flatPack(os);
        }
        os.close();
        byte[] dataToEncrypt = os.toByteArray();

        // Write to a temporary file
        File tempFile = File.createTempFile("upmdb", null);
        FileOutputStream fos = new FileOutputStream(tempFile);

        // Encrypt and format according to the encryption method we're using
        if (isUsingModernEncryption) {
            //Now encrypt the database data using modern encryption
            byte[] encryptedData = modernEncryptionService.encrypt(dataToEncrypt);

            // Write modern format header
            fos.write(MODERN_FILE_HEADER.getBytes());
            fos.write(ModernEncryptionService.FORMAT_VERSION);
            fos.write(modernEncryptionService.getSalt());
            fos.write(encryptedData);
        } else {
            //Now encrypt the database data using legacy encryption
            byte[] encryptedData = encryptionService.encrypt(dataToEncrypt);

            // Write legacy format header
            fos.write(FILE_HEADER.getBytes());
            fos.write(DB_VERSION);
            fos.write(encryptionService.getSalt());
            fos.write(encryptedData);
        }

        fos.close();

        // Rename the tempfile to the real database file
        // The reason for this is to protect against the write thread being
        // terminated thus corrupting the file.
        tempFile.renameTo(databaseFile);
    }

    
    public ArrayList<AccountInformation> getAccounts() {
        return new ArrayList<AccountInformation>(accounts.values());
    }
    
    
    public ArrayList<String> getAccountNames() {
        ArrayList<String> accountNames = new ArrayList<String>(accounts.keySet());
        Collections.sort(accountNames, String.CASE_INSENSITIVE_ORDER);
        return accountNames;
    }


    public File getDatabaseFile() {
        return databaseFile;
    }


    /**
     * There are times when we decrypt a temp version of the database file,
     * e.g. when we download a db during sync. If we end up making this temp db
     * our permanent db then we don't want to have to decrypt it again. In this
     * instance what we do is overwrite the main db file with the temp downloaded
     * one and then repoint this PassswordDatabase at the main db file.  
     * @param file
     */
    public void setDatabaseFile(File file) {
        databaseFile = file;
    }


    public DatabaseOptions getDbOptions() {
        return dbOptions;
    }


    public int getRevision() {
        return revision.getRevision();
    }


    /**
     * Check if the given bytes represent a password database by examining the
     * header bytes for the UPM magic number.
     * @param data
     * @return
     */
    public static boolean isPasswordDatabase(byte[] data) {
        boolean isPasswordDatabase = false;

        if (data == null || data.length <= 3) {
            return false;
        }

        // Check for modern format
        byte[] modernHeaderBytes = new byte[MODERN_FILE_HEADER.getBytes().length];
        if (data.length >= modernHeaderBytes.length) {
            // Copy the header bytes
            System.arraycopy(data, 0, modernHeaderBytes, 0, modernHeaderBytes.length);
            // Check if it matches the modern format header
            if (Arrays.equals(modernHeaderBytes, MODERN_FILE_HEADER.getBytes())) {
                return true;
            }
        }

        // Check for legacy format
        byte[] legacyHeaderBytes = new byte[FILE_HEADER.getBytes().length];
        if (data.length >= legacyHeaderBytes.length) {
            // Copy the header bytes
            System.arraycopy(data, 0, legacyHeaderBytes, 0, legacyHeaderBytes.length);
            // Check if it matches the legacy format header
            if (Arrays.equals(legacyHeaderBytes, FILE_HEADER.getBytes())) {
                return true;
            }
        }

        // If neither header matched, it might still be a pre-v2 database which has no magic header
        // For these we can't really tell just by looking at the header,
        // but at minimum it should have a salt
        return data.length > EncryptionService.SALT_LENGTH;
    }

    public static boolean isPasswordDatabase(File file) throws IOException {
        boolean isPasswordDatabase = false;

        // Check minimum file length
        if (file == null || !file.exists() || file.length() <= 3) {
            return false;
        }

        // Read enough bytes to check for all possible headers
        int bytesToRead = Math.max(MODERN_FILE_HEADER.length(), FILE_HEADER.length()) + 1;
        byte[] data = Util.getBytesFromFile(file, bytesToRead);
        return isPasswordDatabase(data);
    }

    public EncryptionService getEncryptionService() {
        return encryptionService;
    }

    public ModernEncryptionService getModernEncryptionService() {
        return modernEncryptionService;
    }

    public boolean isUsingModernEncryption() {
        return isUsingModernEncryption;
    }

    public String getEncryptionAlgorithm() {
        if (isUsingModernEncryption) {
            return preferChaCha20 ? "ChaCha20-Poly1305 with Argon2id" : "AES-GCM with Argon2id";
        } else {
            return "AES-256-CBC with PBKDF2";
        }
    }
}
