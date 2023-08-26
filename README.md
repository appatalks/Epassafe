# UPM - Epassafe

![logo](https://github.com/appatalks/Epassafe/blob/main/app/src/main/res/drawable/logo.png?raw=true)

---

**UPM - Epassafe (C) 2013** is a fork of Universal Password Manager (UPM) with the development geared towards creating a stand-alone application for Android devices.

UPM - Epassafe differs from Universal Password Manager in several ways. It has been stripped down to the most basic usage, that of encrypting your passwords and allowing backups to be made to an external device (e.g., sdcard).

Grab the latest [Developer Build](https://github.com/appatalks/Epassafe/raw/master/app/build/outputs/apk/debug/app-debug.apk)
Latest: **v3.5** MD5: **0db05a1b667d06e13f7489df4d423bbd**

Or get it from the [Google Play Store](https://play.google.com/store/apps/details?id=com.epassafe.upm&pcampaignid=web_share)

> **NOTE:**
> If upgrading from version <v3.0, you will need to import your backup to `../Android/data/com.epassafe.upm/files/database/` from your PC or connected device. If this is the initial installation on the device, back up a blank database to automatically create the directory and permissions.

> ***History***

> - **v3.5**: General update, moved to [github.com/appatalks/Epassafe](https://github.com/appatalks/Epassafe)
> - **v3.2**: Tweaked Exit code for better performance
> - **v3.1**: Resolved Clipboard Sensitive Data copy issue on Main View
> - **v3.0**: Play Store Release Candidate: Backups stored in `Android/data/com.epassafe.upm/files/database`, permissions no longer needed
> - **v2.9**: Android 13 Clipboard Sensitive Data Recommendation added to Main List view
> - **v2.8**: Fixed annoying Exit Bug
> - **v2.7**: Code Clean up, Additional Android 13 Support improvements
> - **v2.6**: Updated for Android 13 Support
>   - To solve for Android 13 Permissions
>   - Adjusted Password Generator Text Scaling
>   - Logo now in HD
> - **v2.5**: Copy Allowed on Notes View, Expanded lines for Notes Edit
> - **v2.4**: Code Cleanup; App Size Reduced by half, Easter Egg + Game added
> - **v2.3**: Code Cleanup
> - **v2.2** (Aug 2022): Backport Passwords should be invisible to accessibility service. Code Cleanup; Notes Added for Delete from menus - Still not working :/
> - **v2.1** (July 2022): Added Permissions/SDK Updates for Android 11+ in Manifest.
>   - **Still need to manually authorize permissions in Android App Settings**.
>   - Confirmed working with Android 12.
>   - More Code Cleanup
> - **v2.0**: Out of Beta (6 Years Later o.O)
>   - Updated for Android v9.0+ (Q, PIE) 2019.
>   - Updated Build API from 16 to 29.0.1.
>   - Adjusted lockout to 1 hour - very annoying having it auto-lock so quickly.
>   - Code Clean up.
> - **v1.9b Beta**: Changed lockout to 5 mins, added screen keep alive to fix issue of timer not working when phone sleeps.
> - **v1.8b Beta**: Replaced Master Password Warning Text with Logo. (Just don't forget your password!)
>   - Added 10-minute timer to lockout. So no more worries if you forget to lock the app.
> - **v1.7b Beta**: Created an Automatic Backup `aupm.db` from Manual Backup `upm.db` on application exit
>   - **Restore still from Manual Backup file `upm.db`**
>   - If you want to restore automatic backup, must rename `aupm.db` to `upm.db` from the root of sdCard
>     (This makes good practice to do manual backups in the first place, but leaves a safety net for just in case, i.e. database corruption)
> - **v1.6b Beta**: Added Password Generator ([https://github.com/rod86/PassGenerator](https://github.com/rod86/PassGenerator))
> - **v1.5b Beta**: Code Clean Up
> - **v1.4b Beta**: Added Quick Lock with Volume Down (Temporary until figuring out with Screen Off)
> - **v1.3b Beta**: Added Add Account Button to Lists for easy One Click Add Option. Additional Code Clean up.
> - **v1.2b Beta**: Aesthetics and Code Optimization
> - **v1.1b Beta**: Fixed Launch Icon on Some devices not showing up.
> - **v1.0b Beta**: Initial Release

---

## Universal Password Manager

http://upm.sourceforge.net

Copyright (C) 2005-2012 Adrian Smith

Universal Password Manager is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

Universal Password Manager is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with Universal Password Manager; if not, write to the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA

## Overview

Universal Password Manager (UPM) allows you to store usernames, passwords, URLs, and generic notes in an encrypted database protected by one master password.

There are several open source password managers available, so what makes UPM different? Its three strongest features are:

- **Simplicity**: It provides a small number of very strong features with no clutter.
- **Cross-platform**: UPM runs on Android, Windows, Mac OS X, and Linux.
- **Database syncing**: This feature allows you to keep your database in sync across several PCs/devices using either Dropbox or an HTTP location.

## Features

- Small, fast, and lean
- Uses AES for database encryption
- Database sync across multiple PCs/devices
- Written in Java/SWING
- Android, Windows, and Mac OS X native-feeling versions available
- Fast account searching
- Streamlined for those who are more comfortable using the keyboard only

## History

- **v1.14** (28-Oct-2012)
  - Added support for syncing to Dropbox
  - Hide account details in screenshots and task manager

- **v1.13** (12-Aug-2012)
  - Added support for all API levels up to and including 16
  - Fixed a few bugs

- ... (other version history entries)

- **v1.0** (1-Feb-2010)
  - Initial Release
