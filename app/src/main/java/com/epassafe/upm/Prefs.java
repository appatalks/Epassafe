/*
 * Universal Password Manager
 * Copyright (c) 2010-2011 Adrian Smith
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
package com.epassafe.upm;

/**
 * This class only contains constants needed by other parts of the app.
 * The activity implementation has been removed since it's not used,
 * but the constants are preserved for backward compatibility.
 */
public class Prefs {

    // Name of the preferences file
    public static final String PREFS_NAME = "UPMPrefs";

    // Configuration setting constants
    public static final String SYNC_METHOD = "sync.method";

    public interface SyncMethod {
        String DISABLED = "disabled";
        String HTTP = "http";
    }
}
