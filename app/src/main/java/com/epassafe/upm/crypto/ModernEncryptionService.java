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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Universal Password Manager; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
package com.epassafe.upm.crypto;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import android.util.Log;
import android.os.Build;

/**
 * Modern encryption service using AES-GCM or ChaCha20-Poly1305 with enhanced PBKDF2
 * This provides authenticated encryption with associated data (AEAD) and
 * strong key derivation.
 */
public class ModernEncryptionService {

    // Constants for AES-GCM
    public static final String AES_GCM = "AES/GCM/NoPadding";
    public static final int GCM_TAG_LENGTH = 16; // Authentication tag length in bytes
    public static final int GCM_IV_LENGTH = 12; // Recommended IV length for GCM

    // Constants for ChaCha20-Poly1305
    public static final String CHACHA20_POLY1305 = "ChaCha20-Poly1305";
    public static final int CHACHA_NONCE_LENGTH = 12;

    // Constants for key derivation
    public static final int SALT_LENGTH = 16; // 16 bytes / 128 bits
    public static final int HASH_LENGTH = 32; // 32 bytes / 256 bits
    private static final int PBKDF2_ITERATIONS = 310000; // Higher iteration count for security
    private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA512";

    // Flags to identify algorithm used
    public static final byte ALG_AES_GCM = 1;
    public static final byte ALG_CHACHA20_POLY1305 = 2;

    // Shared data
    private static final byte[] DATABASE_HEADER = "UPM_MODERN".getBytes(StandardCharsets.UTF_8);
    public static final byte FORMAT_VERSION = 1;

    // Instance variables
    private SecretKey secretKey;
    private byte[] salt;
    private byte algorithmId;

    static {
        // Register Bouncy Castle provider only for older Android versions
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) { // P is API 28
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Create a new encryption service with a password
     */
    public ModernEncryptionService(char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Generate a new random salt
        SecureRandom secureRandom = new SecureRandom();
        salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);

        // Use enhanced PBKDF2 to derive the key
        deriveKey(password);

        // By default, use AES-GCM
        algorithmId = ALG_AES_GCM;
    }

    /**
     * Create encryption service with existing salt (for decryption)
     */
    public ModernEncryptionService(char[] password, byte[] salt) throws InvalidKeySpecException, NoSuchAlgorithmException {
        if (salt == null || salt.length != SALT_LENGTH) {
            throw new IllegalArgumentException("Invalid salt provided");
        }
        this.salt = salt;
        deriveKey(password);
    }

    /**
     * Use enhanced PBKDF2 to derive the encryption key
     */
    private void deriveKey(char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            // If password is null, we can't derive a key
            if (password == null) {
                throw new InvalidKeySpecException("Password cannot be null");
            }

            // Create key spec using PBKDF2 with SHA-512
            KeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, HASH_LENGTH * 8);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);

            // Generate the secret key bytes
            byte[] keyBytes = keyFactory.generateSecret(spec).getEncoded();

            // Create AES key
            secretKey = new SecretKeySpec(keyBytes, "AES");
        } finally {
            // Ensure we clear the password from memory as soon as possible
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }

    /**
     * Choose which algorithm to use (AES-GCM or ChaCha20-Poly1305)
     */
    public void setAlgorithm(boolean useChaCha) {
        algorithmId = useChaCha ? ALG_CHACHA20_POLY1305 : ALG_AES_GCM;
    }

    /**
     * Encrypt data using the selected algorithm (AES-GCM by default)
     */
    public byte[] encrypt(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException,
            NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        if (secretKey == null) {
            throw new IllegalStateException("Encryption key has not been initialized");
        }

        try {
            if (algorithmId == ALG_CHACHA20_POLY1305) {
                try {
                    return encryptChaCha20Poly1305(plaintext);
                } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                    // ChaCha20-Poly1305 not available on this device
                    Log.w("ModernEncryptionService", "ChaCha20-Poly1305 not available, falling back to AES-GCM", e);
                    // Switch to AES-GCM
                    algorithmId = ALG_AES_GCM;
                    return encryptAesGcm(plaintext);
                }
            } else {
                return encryptAesGcm(plaintext);
            }
        } catch (Exception e) {
            Log.e("ModernEncryptionService", "Encryption failed", e);
            throw new RuntimeException("Encryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * Decrypt data by determining which algorithm was used
     */
    public byte[] decrypt(byte[] ciphertext) throws InvalidPasswordException {
        if (secretKey == null) {
            throw new IllegalStateException("Decryption key has not been initialized");
        }

        try {
            // Make sure we have data to decrypt
            if (ciphertext == null || ciphertext.length < 2) {
                throw new InvalidPasswordException("Invalid encrypted data");
            }

            // First byte indicates algorithm
            byte algorithm = ciphertext[0];
            byte[] actualData = Arrays.copyOfRange(ciphertext, 1, ciphertext.length);

            if (algorithm == ALG_CHACHA20_POLY1305) {
                try {
                    return decryptChaCha20Poly1305(actualData);
                } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
                    Log.w("ModernEncryptionService", "ChaCha20-Poly1305 not available for decryption", e);
                    throw new InvalidPasswordException("ChaCha20-Poly1305 algorithm not supported on this device. Try using AES-GCM instead.");
                }
            } else if (algorithm == ALG_AES_GCM) {
                return decryptAesGcm(actualData);
            } else {
                throw new InvalidPasswordException("Unknown encryption algorithm: " + algorithm);
            }
        } catch (InvalidPasswordException e) {
            throw e;
        } catch (Exception e) {
            Log.e("ModernEncryptionService", "Decryption failed", e);
            throw new InvalidPasswordException("Decryption failed: " + e.getMessage());
        }
    }

    /**
     * Encrypt data using AES-GCM
     */
    private byte[] encryptAesGcm(byte[] plaintext) throws NoSuchAlgorithmException, NoSuchPaddingException,
            NoSuchProviderException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

        // Generate random IV
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);

        // Initialize cipher
        Cipher cipher = Cipher.getInstance(AES_GCM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);

        // Add associated data (header) for additional security
        cipher.updateAAD(DATABASE_HEADER);

        // Perform encryption
        byte[] ciphertext = cipher.doFinal(plaintext);

        // Format: [Algorithm (1 byte)][IV (12 bytes)][Ciphertext + Auth Tag]
        ByteBuffer byteBuffer = ByteBuffer.allocate(1 + iv.length + ciphertext.length);
        byteBuffer.put(ALG_AES_GCM);
        byteBuffer.put(iv);
        byteBuffer.put(ciphertext);

        return byteBuffer.array();
    }

    /**
     * Decrypt data using AES-GCM
     */
    private byte[] decryptAesGcm(byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException,
            NoSuchProviderException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

        // Extract IV
        byte[] iv = Arrays.copyOfRange(data, 0, GCM_IV_LENGTH);

        // Extract ciphertext (the IV length to the end, including auth tag)
        byte[] ciphertext = Arrays.copyOfRange(data, GCM_IV_LENGTH, data.length);

        // Initialize cipher
        Cipher cipher = Cipher.getInstance(AES_GCM);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

        // Add associated data (header) for additional security
        cipher.updateAAD(DATABASE_HEADER);

        // Perform decryption
        return cipher.doFinal(ciphertext);
    }

    /**
     * Encrypt data using ChaCha20-Poly1305
     */
    private byte[] encryptChaCha20Poly1305(byte[] plaintext) throws NoSuchAlgorithmException, NoSuchPaddingException,
            NoSuchProviderException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

        // Generate random nonce
        SecureRandom secureRandom = new SecureRandom();
        byte[] nonce = new byte[CHACHA_NONCE_LENGTH];
        secureRandom.nextBytes(nonce);

        // Initialize cipher
        Cipher cipher = Cipher.getInstance(CHACHA20_POLY1305);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

        // Add associated data (header) for additional security
        cipher.updateAAD(DATABASE_HEADER);

        // Perform encryption
        byte[] ciphertext = cipher.doFinal(plaintext);

        // Format: [Algorithm (1 byte)][Nonce (12 bytes)][Ciphertext + Auth Tag]
        ByteBuffer byteBuffer = ByteBuffer.allocate(1 + nonce.length + ciphertext.length);
        byteBuffer.put(ALG_CHACHA20_POLY1305);
        byteBuffer.put(nonce);
        byteBuffer.put(ciphertext);

        return byteBuffer.array();
    }

    /**
     * Decrypt data using ChaCha20-Poly1305
     */
    private byte[] decryptChaCha20Poly1305(byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException,
            NoSuchProviderException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

        // Extract nonce
        byte[] nonce = Arrays.copyOfRange(data, 0, CHACHA_NONCE_LENGTH);

        // Extract ciphertext (the nonce length to the end, including auth tag)
        byte[] ciphertext = Arrays.copyOfRange(data, CHACHA_NONCE_LENGTH, data.length);

        // Initialize cipher
        Cipher cipher = Cipher.getInstance(CHACHA20_POLY1305);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

        // Add associated data (header) for additional security
        cipher.updateAAD(DATABASE_HEADER);

        // Perform decryption
        return cipher.doFinal(ciphertext);
    }

    /**
     * Get the salt used for key derivation
     */
    public byte[] getSalt() {
        return salt;
    }

    /**
     * Get the current secret key
     */
    public SecretKey getSecretKey() {
        return secretKey;
    }
}
