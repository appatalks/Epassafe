# Epassafe

![logo](https://github.com/appatalks/Epassafe/blob/main/app/src/main/res/drawable/logo.png?raw=true)

---

**Epassafe (C) 2025** is a modern **no nonsense Password Manager** for Android devices.

Epassafe, a Password Manager of the most basic usage, that of encrypting your passwords using modern cryptography and allowing backups to be made to an external device (e.g., sdcard). 

Grab the latest [Developer Build](https://github.com/appatalks/Epassafe/raw/refs/heads/main/app/release/app-release.apk)

Latest: **v3.9** MD5: ```157de69a13198e2dda42435ca4a16840  app/release/app-release.apk``` ```May '25```

Or get it from the [Google Play Store](https://play.google.com/store/apps/details?id=com.epassafe.upm&pcampaignid=web_share)

> [!IMPORTANT]
> Backup and Restore $PATH is through `../Android/data/com.epassafe.upm/files/database/`. If this is the initial installation on the device, restore a blank database to automatically create the directory and permissions, then restore the backup as "`upm.db`".

<details>

<summary>Changelog</summary>

```markdown
***History***

 - **v4.0**: Android Updates, double login patch fix
 - **v3.9**: Code cleanup, corrections - Argon2id not used.  
 - **v3.8**: (May 2025) Major updates, including modern cryptography options, export-to-cvs, bug fixes
 - **v3.7**: Android SDK Target 35; Minor updates, bug fixes.
 - **v3.5**: General update, moved to [github.com/appatalks/Epassafe](https://github.com/appatalks/Epassafe)
 - **v3.2**: Tweaked Exit code for better performance
 - **v3.1**: Resolved Clipboard Sensitive Data copy issue on Main View
 - **v3.0**: Play Store Release Candidate: Backups stored in `Android/data/com.epassafe.upm/files/database`, permissions no longer needed
 - **v2.9**: Android 13 Clipboard Sensitive Data Recommendation added to Main List view
 - **v2.8**: Fixed annoying Exit Bug
 - **v2.7**: Code Clean up, Additional Android 13 Support improvements
 - **v2.6**: Updated for Android 13 Support
   - To solve for Android 13 Permissions
   - Adjusted Password Generator Text Scaling
   - Logo now in HD
 - **v2.5**: Copy Allowed on Notes View, Expanded lines for Notes Edit
 - **v2.4**: Code Cleanup; App Size Reduced by half, Easter Egg + Game added
 - **v2.3**: Code Cleanup
 - **v2.2** (Aug 2022): Backport Passwords should be invisible to accessibility service. Code Cleanup; Notes Added for Delete from menus - Still not working :/
 - **v2.1** (July 2022): Added Permissions/SDK Updates for Android 11+ in Manifest.
   - **Still need to manually authorize permissions in Android App Settings**.
   - Confirmed working with Android 12.
   - More Code Cleanup
 - **v2.0**: Out of Beta (6 Years Later o.O)
   - Updated for Android v9.0+ (Q, PIE) 2019.
   - Updated Build API from 16 to 29.0.1.
   - Adjusted lockout to 1 hour - very annoying having it auto-lock so quickly.
   - Code Clean up.
 - **v1.9b Beta**: Changed lockout to 5 mins, added screen keep alive to fix issue of timer not working when phone sleeps.
 - **v1.8b Beta**: Replaced Master Password Warning Text with Logo. (Just don't forget your password!)
   - Added 10-minute timer to lockout. So no more worries if you forget to lock the app.
 - **v1.7b Beta**: Created an Automatic Backup `aupm.db` from Manual Backup `upm.db` on application exit
   - **Restore still from Manual Backup file `upm.db`**
   - If you want to restore automatic backup, must rename `aupm.db` to `upm.db` from the root of sdCard
     (This makes good practice to do manual backups in the first place, but leaves a safety net for just in case, i.e. database corruption)
 - **v1.6b Beta**: Added Password Generator ([https://github.com/rod86/PassGenerator](https://github.com/rod86/PassGenerator))
 - **v1.5b Beta**: Code Clean Up
 - **v1.4b Beta**: Added Quick Lock with Volume Down (Temporary until figuring out with Screen Off)
 - **v1.3b Beta**: Added Add Account Button to Lists for easy One Click Add Option. Additional Code Clean up.
 - **v1.2b Beta**: Aesthetics and Code Optimization
 - **v1.1b Beta**: Fixed Launch Icon on Some devices not showing up.
 - **v1.0b Beta**: (2013) Initial Release
```

</details>

---

---

**Epassafe is heavily modifed from the original Author's amazing work which is no longer maintained**

```md
## Universal Password Manager

http://upm.sourceforge.net
https://github.com/adrian/upm-android

Copyright (C) 2005-2012 Adrian Smith
```

