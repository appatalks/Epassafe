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
package com.epassafe.upm.database;


@SuppressWarnings("serial")
public class ProblemReadingDatabaseFile extends Exception {
    
    public ProblemReadingDatabaseFile(String message) {
        super(message);
    }

    
    public ProblemReadingDatabaseFile(String message, Throwable cause) {
        super(message, cause);
    }
    
}
