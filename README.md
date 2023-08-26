﻿UPM - Epassafe
![logo](https://github.com/appatalks/Epassafe/blob/main/app/src/main/res/drawable/logo.png?raw=true)
--------------------------
UPM - Epassafe (C) 2013 is a fork of Universal Password Manager (UPM) with the
development geared to making this a stand-alone application on an Android Device.

UPM - Epassafe differs from Universal Password Manager in several ways. It has been
stripped down to the most basic usage, that of encrypting your passwords and allowing
backups to be made to external device i.e sdcard. 

Grab latest [Developer Build](https://github.com/appatalks/Epassafe/raw/master/app/build/outputs/apk/debug/app-debug.apk)
Latest: v3.5 MD5 0db05a1b667d06e13f7489df4d423bbd

Ir grab it from the [Google Play Store](https://play.google.com/store/apps/details?id=com.epassafe.upm&pcampaignid=web_share)

** NOTE **
If upgrading from <v.3.0, you will need to import your backup to "../Android/data/com.epassafe.upm/files/database/" from your PC or connected device.
If first inital install on device, go ahead and backup a blank database to auto create the directory/permissions. 

History
-------
v.3.5 - General update, move to github.com/appatalks/Epassafe
v.3.2 - Tweaking Exit code for better performance
v.3.1 - Resolved ClipBoard Sensitive Data copy issue on Main View
v.3.0 - Play Store Release Candidate : Backups stored in Android/data/com.epassafe.upm/files/database
	Permissions no longer needed
v.2.9 - Android 13 Clipboard Sensitive Data Recommendation added to Main List view.
v.2.8 - Fixed annoying Exit Bug
v.2.7 - Code Clean up, Additional Android 13 Support improvements.
v.2.6 - Updated for Android 13 Support
          To solve for Android 13 Permissions.
        Adjusted Password Generator Text Scaling
        Logo now in HD
v.2.5 - Copy Allowed on Notes View, Expanded lines for Notes Edit
v.2.4 - Code Cleanup; App Size Reduced by half. Easter Egg + Game added
v.2.3 - Code Cleanup
v.2.2 - (Aug 2022) Backport Passwords should be invisible to accessibility service. 
        Code Cleanup; Notes Added for Delete from menus - Still not working :/
v.2.1 – (July 2022) Added Permissions/SDK Updates for Android 11+ in Manifest.
        ** Still need to manually auth permissions in Android App Settings). 
        Confirmed working with Android 12.
	More Code Cleanup
v.2.0 - Out of Beta (6 Years Later o.O)
        Updated for Android v9.0+ (Q, PIE) 2019.
        Updated Build API from 16 to 29.0.1.
        Adjusted lockout to 1 hour - very annoying having it auto-lock so quickly. 
        Code Clean up.
            
v.1.9b Beta - Changed lockout to 5 mins, added screen keep alive to fix issue of timer not working when phone sleeps.
v.1.8b Beta - Replaced Master Password Warning Text with Logo. (Just don't forget your password!)
	      Added 10 minute timer to lockout. So no more worries if you forget to lock the app.
v.1.7b Beta - Created an Automatic Backup aupm.db from Manual Backup upm.db on application exit
	      --Restore still from Manual Backup file upm.db
	      --If want to restore automatic backup, must rename aupm.db --> upm.db from root of sdCard
	       (This makes good practice to do manual backups in the first place, but leaves a safety net
	        for just in case i.e. database corruption)
v.1.6b Beta - Added Password Generator (https://github.com/rod86/PassGenerator)
v.1.5b Beta - Code Clean Up
v.1.4b Beta - Added Quick Lock with Volume Down (Temp until figure out with Screen Off)
v.1.3B Beta - Added Add Account Button to Lists for easy One Click Add Option. Additional Code Clean up.
v.1.2b Beta - Esthetics and Code Optimization
v.1.1b Beta - Fixed Launch Icon on Some devices not showing up.
v.1.0b Beta Initial Release 
 


Universal Password Manager
--------------------------
http://upm.sourceforge.net

Copyright (C) 2005-2012 Adrian Smith

Universal Password Manager is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

Universal Password Manager is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Universal Password Manager; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA


Overview
--------
   Universal Password Manager (UPM) allows you to store usernames, passwords, URLs,
   and generic notes in an encrypted database protected by one master password.

   There are several open source password managers available so what makes UPM 
   different? It's three strongest features are...

    * it's simplicity - it provides a small number of very strong features with no
      clutter.

    * cross platform - UPM runs on Android, Windows, Mac OS X and Linux.

    * database syncing - This feature allows your to keep you database in sync
      across several PCs/devices using either Dropbox or a HTTP location.

Features
--------
   .Small, fast and lean
   .Uses AES for database encryption
   .Database sync across multiple PCs/devices
   .Written in Java/SWING
   .Android, Windows and Mac OS X native feeling versions available
   .Fast account searching
   .Streamlined for those who are more comfortable using the keyboard only

History
-------
   v1.14 28-Oct-2012
     * Added support for syncing to Dropbox
     * Hide account details in screenshots and task manager

   v1.13 12-Aug-2012
     * Added support for all API levels up to and including 16
     * Fixed a few bugs

   v1.12 23-Jan-2012
     * Added support for version 3 of the password database. This version stores all strings as UTF-8.

   v1.11 08-Jan-2012
     * Bug fix release

   v1.10 12-Dec-2011
     * Bug fix release

   v1.9 06-Dec-2011
     * Bug fix release

   v1.8 12-Oct-2011
     * Added Russian translation
     * Trim the remote url before using it

   v1.7 17-Jul-2011
     * Added permission WRITE_EXTERNAL_STORAGE. Backup wasn't working without this.

   v1.6 17-Jul-2011
     * When returning to the main account list activity return to the same scroll position as we left
     * Added support for large screens
     * Made links on the Account Details page clickable

   v1.5 29-Nov-2010
     * Moved all buttons onto a ButtonBar on their respective Activity
     * Put a "Restore Database" option on the New Database dialog

   v1.4 21-Oct-2010
     * Bugfix for blank screen when the application starts

   v1.3 14-Oct-2010
     * Fixed a number of problems that were causing crashes.
     * Delete the temp db file created during a sync operation.

   v1.2 8-Aug-2010
     * New Feature: Long-clicking on an account now brings up a context menu
       allowing you to copy username, copy password, launch URL, edit account
     * New Feature: Added the ability to trust self signed certificates and 
       certificates that have a different Common Name to the website hostname
     * New Feature: Increased the font size on the Account Details activity
     * Bug Fix: recover gracefully when the database is closed unexpectedly

   v1.1 30-Mar-2010
     * Implemented the Shared Database feature as it exists in the desktop
       version of UPM
     * Added Delete Database feature
     * Lots of little bugs fixes throughout the codebase

   v1.0 1-Feb-2010
     * Initial Release