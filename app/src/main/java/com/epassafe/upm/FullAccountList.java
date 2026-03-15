/* 
 * 
 * Universal Password Manager 
 * Copyright (c) 2010-2011 Adrian Smith - MODIFIED By Steven Bennett for UPM - Epassafe
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
package com.epassafe.upm;

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager.NameNotFoundException;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.util.Log;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
/* END */ 

public class FullAccountList extends AccountsList {

    private static final int CONFIRM_RESTORE_DIALOG = 0;
    private static final int CONFIRM_OVERWRITE_BACKUP_FILE = 1;
    private static final int DIALOG_ABOUT = 2;
    private static final int CONFIRM_DELETE_DB_DIALOG = 3;
    private static final int CONFIRM_OVERWRITE_BACKUP_DOWNLOADS = 4;
    private static final int CONFIRM_RESTORE_DOWNLOADS_DIALOG = 5;

    public static final int RESULT_EXIT = 0;
    public static final int RESULT_ENTER_PW = 1;

    private static final int REQ_CODE_PICK_RESTORE_FILE = 100;
    private Uri pendingRestoreUri;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        registerForContextMenu(getListView());
        populateAccountList();
    }
    
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent intent) {
        switch(requestCode) {
            case AddEditAccount.EDIT_ACCOUNT_REQUEST_CODE:
            case ViewAccountDetails.VIEW_ACCOUNT_REQUEST_CODE:
                if (resultCode == AddEditAccount.EDIT_ACCOUNT_RESULT_CODE_TRUE) {
                    populateAccountList();
                }
                break;
            case REQ_CODE_PICK_RESTORE_FILE:
                if (resultCode == RESULT_OK && intent != null && intent.getData() != null) {
                    pendingRestoreUri = intent.getData();
                    showDialog(CONFIRM_RESTORE_DOWNLOADS_DIALOG);
                }
                break;
        }
    }

    private void populateAccountList() {
        if (getPasswordDatabase() == null) {
            // If the UPM process was restarted since AppEntryActivity was last
            // run then databaseFileToDecrypt won't be set so set it here.
            EnterMasterPassword.databaseFileToDecrypt = Utilities.getDatabaseFile(this);
            setResult(RESULT_ENTER_PW);
            finish();
        } else {
            setListAdapter(new ArrayAdapter<String>(this, android.R.layout.simple_list_item_1, getPasswordDatabase().getAccountNames()));
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        super.onCreateOptionsMenu(menu);   

       MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.main, menu);

        /* ADD BUTTON */        
    		MenuItem item = menu.add(0, R.id.add, 0, R.string.add);
    		item.setShortcut('4', 'a');
    		item.setIcon(R.drawable.ic_menu_add_password);
    		item.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);
    		return super.onCreateOptionsMenu(menu);
        }
        /* END ADD BUTTON */
    
    /* POWER LOCK AND EXIT LOCK */
    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (keyCode == KeyEvent.KEYCODE_BACK) {
            new AlertDialog.Builder(this)
            .setIcon(android.R.drawable.ic_dialog_alert)
            .setTitle(R.string.confirm_exit_title)
            .setMessage(R.string.confirm_exit_message)
            .setPositiveButton(R.string.yes, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    FullAccountList.this.setResult(RESULT_ENTER_PW);
                    FullAccountList.this.finish();
                }
            })
            .setNegativeButton(R.string.no, null)
            .show();
            return true;
        } 
        else if (keyCode == KeyEvent.KEYCODE_VOLUME_DOWN){
        	Intent i = new Intent(FullAccountList.this, AppEntryActivity.class);
            i.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
            startActivity(i);
            finish();
            return true;
        }
        else {
            return super.onKeyDown(keyCode, event);
        }
    } 
    /* End */
    
    @SuppressWarnings("deprecation")
	@Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int itemId = item.getItemId();
        if (itemId == R.id.search) {
            onSearchRequested();
            return true;
        } else if (itemId == R.id.add) {
            Intent i = new Intent(FullAccountList.this, AddEditAccount.class);
            i.putExtra(AddEditAccount.MODE, AddEditAccount.ADD_MODE);
            startActivityForResult(i, AddEditAccount.EDIT_ACCOUNT_REQUEST_CODE);
            return true;
        } else if (itemId == R.id.change_master_password) {
            startActivity(new Intent(FullAccountList.this, ChangeMasterPassword.class));
            return true;
        } else if (itemId == R.id.about) {
            showDialog(DIALOG_ABOUT);
            return true;
        } else if (itemId == R.id.backup_downloads) {
            if (((UPMApplication) getApplication()).downloadsBackupExists(this)) {
                showDialog(CONFIRM_OVERWRITE_BACKUP_DOWNLOADS);
            } else {
                backupToDownloads();
            }
            return true;
        } else if (itemId == R.id.restore_downloads) {
            // Launch SAF file picker to select a database file
            Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            intent.setType("*/*");
            startActivityForResult(intent, REQ_CODE_PICK_RESTORE_FILE);
            return true;
        } else if (itemId == R.id.delete_db) {
            showDialog(CONFIRM_DELETE_DB_DIALOG);
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    @Override
    protected Dialog onCreateDialog(int id) {
        AlertDialog.Builder dialogBuilder = new AlertDialog.Builder(this);

        switch (id) {
            case CONFIRM_RESTORE_DIALOG:
                dialogBuilder.setMessage(getString(R.string.confirm_restore_overwrite))
                        .setCancelable(false)
                        .setPositiveButton(R.string.yes, new DialogInterface.OnClickListener() {
                            public void onClick(DialogInterface dialog, int id) {
                                ((UPMApplication) getApplication()).restoreDatabase(FullAccountList.this);
                                // Clear the activity stack and bring up AppEntryActivity
                                // This is effectively restarting the application
                                Intent i = new Intent(FullAccountList.this, AppEntryActivity.class);
                                i.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
                                startActivity(i);
                                finish();
                            }
                        })
                        .setNegativeButton(R.string.no, new DialogInterface.OnClickListener() {
                            public void onClick(DialogInterface dialog, int id) {
                                dialog.cancel();
                            }
                        });
                break;
            case CONFIRM_OVERWRITE_BACKUP_FILE:
                File backupFile = new File(getExternalFilesDir("database"), Utilities.DEFAULT_DATABASE_FILE);
                String messageRes = getString(R.string.backup_file_exists);
                String message = String.format(messageRes, backupFile.getAbsolutePath());

                dialogBuilder.setMessage(message)
                        .setCancelable(false)
                        .setPositiveButton(R.string.yes, new DialogInterface.OnClickListener() {
                            public void onClick(DialogInterface dialog, int id) {
                                backupDatabase();
                            }
                        })
                        .setNegativeButton(R.string.no, new DialogInterface.OnClickListener() {
                            public void onClick(DialogInterface dialog, int id) {
                                dialog.cancel();
                            }
                        });
                break;
            case DIALOG_ABOUT:
                PackageInfo pinfo;
                String versionName = "<unknown>";
                try {
                    pinfo = getPackageManager().getPackageInfo(getPackageName(), 0);
                    versionName = pinfo.versionName;
                } catch (NameNotFoundException e) {
                    Log.e("FullAccountList", e.getMessage(), e);
                }

                View v = LayoutInflater.from(this).inflate(R.layout.dialog, null);
                TextView text = v.findViewById(R.id.dialogText);
                text.setText(getString(R.string.aboutText, versionName));

                dialogBuilder
                        .setTitle(R.string.about)
                        .setIcon(android.R.drawable.ic_menu_info_details)
                        .setNegativeButton(R.string.close, null)
                        .setView(v);
                break;
            /* Clear Activity may be able to also allow Lock */
            case CONFIRM_DELETE_DB_DIALOG:
                dialogBuilder.setMessage(getString(R.string.confirm_delete_db))
                        .setPositiveButton(R.string.yes, new DialogInterface.OnClickListener() {
                            public void onClick(DialogInterface dialog, int id) {
                                deleteDatabase();
                                // Clear the activity stack and bring up AppEntryActivity
                                // This is effectively restarting the application
                                Intent i = new Intent(FullAccountList.this, AppEntryActivity.class);
                                i.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
                                startActivity(i);
                                finish();
                            }
                        })
                        .setNegativeButton(R.string.no, new DialogInterface.OnClickListener() {
                            public void onClick(DialogInterface dialog, int id) {
                                dialog.cancel();
                            }
                        });
                break;

            case CONFIRM_OVERWRITE_BACKUP_DOWNLOADS:
                dialogBuilder.setMessage(getString(R.string.backup_downloads_exists))
                        .setCancelable(false)
                        .setPositiveButton(R.string.yes, new DialogInterface.OnClickListener() {
                            public void onClick(DialogInterface dialog, int id) {
                                backupToDownloads();
                            }
                        })
                        .setNegativeButton(R.string.no, new DialogInterface.OnClickListener() {
                            public void onClick(DialogInterface dialog, int id) {
                                dialog.cancel();
                            }
                        });
                break;

            case CONFIRM_RESTORE_DOWNLOADS_DIALOG:
                dialogBuilder.setMessage(getString(R.string.confirm_restore_downloads))
                        .setCancelable(false)
                        .setPositiveButton(R.string.yes, new DialogInterface.OnClickListener() {
                            public void onClick(DialogInterface dialog, int id) {
                                if (pendingRestoreUri != null) {
                                    boolean success = ((UPMApplication) getApplication())
                                            .restoreFromUri(FullAccountList.this, pendingRestoreUri);
                                    pendingRestoreUri = null;
                                    if (success) {
                                        Toast.makeText(FullAccountList.this,
                                                R.string.restore_downloads_success, Toast.LENGTH_LONG).show();
                                        // Restart the app to load the restored database
                                        Intent i = new Intent(FullAccountList.this, AppEntryActivity.class);
                                        i.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
                                        startActivity(i);
                                        finish();
                                    }
                                }
                            }
                        })
                        .setNegativeButton(R.string.no, new DialogInterface.OnClickListener() {
                            public void onClick(DialogInterface dialog, int id) {
                                pendingRestoreUri = null;
                                dialog.cancel();
                            }
                        });
                break;

        }
        return dialogBuilder.create();
    }

    private void deleteDatabase() {
        Utilities.getDatabaseFile(this).delete();
        Utilities.setDatabaseFileName(null, this);
    }

    private void backupDatabase() {
        File fileOnSDCard = new File(getExternalFilesDir("database"), Utilities.DEFAULT_DATABASE_FILE);
        File databaseFile = Utilities.getDatabaseFile(this);
        if (((UPMApplication) getApplication()).copyFile(databaseFile, fileOnSDCard, this)) {
            String message = String.format(getString(R.string.backup_complete), fileOnSDCard.getAbsolutePath());
            UIUtilities.showToast(this, message, false);
        }
    }

    private void backupToDownloads() {
        if (((UPMApplication) getApplication()).backupToDownloads(this)) {
            UIUtilities.showToast(this, getString(R.string.backup_downloads_complete), false);
        }
    }

}
