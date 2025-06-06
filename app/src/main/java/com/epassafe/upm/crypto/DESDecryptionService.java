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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
package com.epassafe.upm.crypto;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;


public class DESDecryptionService {

    // Legacy algorithm (insecure, kept for backwards compatibility only)
    public static final String PBEWithMD5AndDES = "PBEWithMD5AndDES";

    // Secure algorithm for new encryption
    public static final String PBEWithSHA256And256BitAES = "PBEWithSHA256And256BitAES-CBC-BC";


    /**
     * This method initialises a local decryption cipher, and decrypts the given string.
     * It's here as a convenience method for backwards compatibility with the old DES
     * encryption algorithm pre 1.3
     * @param password
     * @param salt
     * @param ciphertext
     * @return The decrypted bytes
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws InvalidPasswordException
     */
    public static byte[] decrypt(char[] password, byte[] salt, byte[] ciphertext) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, InvalidPasswordException {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password);
        SecretKeyFactory keyFac = SecretKeyFactory.getInstance(PBEWithMD5AndDES);
        SecretKey secretKey = keyFac.generateSecret(pbeKeySpec);

        return decrypt(secretKey, salt, ciphertext);
    }


    public static byte[] decrypt(SecretKey secretKey, byte[] salt, byte[] ciphertext) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, InvalidPasswordException {
        PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, 20);
        Cipher desDecryptionCipher = Cipher.getInstance(PBEWithMD5AndDES);
        desDecryptionCipher.init(Cipher.DECRYPT_MODE, secretKey, pbeParamSpec);

        // Do the decryption
        byte[] retVal;
        try {
            retVal = desDecryptionCipher.doFinal(ciphertext);
        } catch (BadPaddingException e) {
            throw new InvalidPasswordException();
        }
        return retVal;
    }

    /**
     * Secure decryption using AES for new databases
     * @param password
     * @param salt
     * @param ciphertext
     * @return The decrypted bytes
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws InvalidPasswordException
     */
    public static byte[] decryptAES(char[] password, byte[] salt, byte[] ciphertext) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, InvalidPasswordException {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password);
        SecretKeyFactory keyFac = SecretKeyFactory.getInstance(PBEWithSHA256And256BitAES);
        SecretKey secretKey = keyFac.generateSecret(pbeKeySpec);

        return decryptAES(secretKey, salt, ciphertext);
    }


    public static byte[] decryptAES(SecretKey secretKey, byte[] salt, byte[] ciphertext) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, InvalidPasswordException {
        PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, 20);
        Cipher aesDecryptionCipher = Cipher.getInstance(PBEWithSHA256And256BitAES);
        aesDecryptionCipher.init(Cipher.DECRYPT_MODE, secretKey, pbeParamSpec);

        // Do the decryption
        byte[] retVal;
        try {
            retVal = aesDecryptionCipher.doFinal(ciphertext);
        } catch (BadPaddingException e) {
            throw new InvalidPasswordException();
        }
        return retVal;
    }
}
