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

import com.epassafe.upm.database.AccountInformation;
import com.epassafe.upm.database.PasswordDatabase;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Exports database contents to various formats
 */
public class DatabaseExporter {
    private static final String TAG = "DatabaseExporter";

    /**
     * Export database contents to a CSV file
     * @param database The decrypted password database
     * @param outputFile The file to write CSV data to
     * @return true if successful, false if failed
     */
    public static boolean exportToCSV(PasswordDatabase database, File outputFile) {
        if (database == null || outputFile == null) {
            Log.e(TAG, "Invalid parameters for CSV export");
            return false;
        }

        try {
            // Create parent directories if they don't exist
            File parentDir = outputFile.getParentFile();
            if (parentDir != null && !parentDir.exists()) {
                parentDir.mkdirs();
            }

            // Get all accounts
            ArrayList<AccountInformation> accounts = database.getAccounts();

            // Open file for writing with UTF-8 encoding
            FileOutputStream fos = new FileOutputStream(outputFile);
            OutputStreamWriter writer = new OutputStreamWriter(fos, StandardCharsets.UTF_8);

            // Write CSV header
            writer.write("Account Name,Username,Password,URL,Notes\n");

            // Write account data
            for (AccountInformation account : accounts) {
                writer.write(escapeCSV(account.getAccountName()) + ",");
                writer.write(escapeCSV(account.getUserId()) + ",");
                writer.write(escapeCSV(account.getPassword()) + ",");
                writer.write(escapeCSV(account.getUrl()) + ",");
                writer.write(escapeCSV(account.getNotes()) + "\n");
            }

            writer.flush();
            writer.close();
            fos.close();

            Log.i(TAG, "Successfully exported " + accounts.size() + " accounts to CSV");
            return true;

        } catch (IOException e) {
            Log.e(TAG, "Error exporting database to CSV", e);
            return false;
        }
    }

    /**
     * Properly escape a field for CSV output
     */
    private static String escapeCSV(String input) {
        if (input == null) {
            return "";
        }

        // If the field contains quotes, commas or newlines, it needs to be quoted and
        // internal quotes need to be doubled
        boolean needsQuotes = input.contains("\"") || input.contains(",") ||
                             input.contains("\n") || input.contains("\r");

        if (needsQuotes) {
            // Replace any quotes with double quotes
            String escaped = input.replace("\"", "\"\"");
            return "\"" + escaped + "\"";
        }

        return input;
    }
}
