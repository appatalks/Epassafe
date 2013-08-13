/* 
 * 
 * Universal Password Manager 
 \* Copyright (c) 2010-2011 Adrian Smith - MODDIFIED By Steven Bennett for UPM - Epassafe- MODDIFIED By Steven Bennett for UPM - Epassafe
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

import java.io.File;

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager.NameNotFoundException;
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

/* Button */
import com.epassafe.upm.wrappers.CheckWrappers;
import com.epassafe.upm.wrappers.honeycomb.WrapActionBar;
/* END */ 

public class FullAccountList extends AccountsList {

    private static final int CONFIRM_RESTORE_DIALOG = 0;
    private static final int CONFIRM_OVERWRITE_BACKUP_FILE = 1;
    private static final int DIALOG_ABOUT = 2;
    private static final int CONFIRM_DELETE_DB_DIALOG = 3;
    
    /* DELETE FROM CONTEXT NOT WORKING ATM*/
 // NEED TO FIGURE THIS ONE OUT
    /* DELETE END */
    
    public static final int RESULT_EXIT = 0;
    public static final int RESULT_ENTER_PW = 1;
    
    
//    public static final String CERT_FILE_NAME = "upm.cer";

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
    		if (CheckWrappers.mActionBarAvailable) {
    			item.setIcon(R.drawable.ic_menu_add_password);
    			WrapActionBar.showIfRoom(item);
    		
    		} else {
    			item.setIcon(android.R.drawable.ic_menu_add);}
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
        boolean optionConsumed = false;

        switch (item.getItemId()) {
            case R.id.search:
                onSearchRequested();
                optionConsumed = true;
                break;
            case R.id.add:
                if (Utilities.isSyncRequired(this)) {
                    UIUtilities.showToast(this, R.string.sync_required);
                } else {
                    Intent i = new Intent(FullAccountList.this, AddEditAccount.class);
                    i.putExtra(AddEditAccount.MODE, AddEditAccount.ADD_MODE);
                    startActivityForResult(i, AddEditAccount.EDIT_ACCOUNT_REQUEST_CODE);
                }
                break;
            case R.id.change_master_password:
                if (Utilities.isSyncRequired(this)) {
                    UIUtilities.showToast(this, R.string.sync_required);
                } else {
                    startActivity(new Intent(FullAccountList.this, ChangeMasterPassword.class));
                }
                break;
            case R.id.restore:
                // Check to ensure there's a file to restore
                File restoreFile = new File(Environment.getExternalStorageDirectory(), Utilities.DEFAULT_DATABASE_FILE);
                if (restoreFile.exists()) {
                    showDialog(CONFIRM_RESTORE_DIALOG);
                } else {
                    String messageRes = getString(R.string.restore_file_doesnt_exist);
                    String message = String.format(messageRes, restoreFile.getAbsolutePath());
                    Toast.makeText(this, message, Toast.LENGTH_LONG).show();
                }
                break;
            case R.id.backup:
                // If there's already a backup file prompt the user if they want to overwrite
                File backupFile = new File(Environment.getExternalStorageDirectory(), Utilities.DEFAULT_DATABASE_FILE);
                if (backupFile.exists()) {
                    showDialog(CONFIRM_OVERWRITE_BACKUP_FILE);
                } else {
                    backupDatabase();
                }
                break;
            case R.id.about:
                showDialog(DIALOG_ABOUT);
                break;
            case R.id.delete_db:
                showDialog(CONFIRM_DELETE_DB_DIALOG);
                break;
                         
        }

        return optionConsumed;
    }

    @Override
    protected Dialog onCreateDialog(int id) {
        AlertDialog.Builder dialogBuilder = new AlertDialog.Builder(this);

        switch(id) {
        case CONFIRM_RESTORE_DIALOG:
            dialogBuilder.setMessage(getString(R.string.confirm_restore_overwrite))
               .setCancelable(false)
               .setPositiveButton("Yes", new DialogInterface.OnClickListener() {
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
               .setNegativeButton("No", new DialogInterface.OnClickListener() {
                   public void onClick(DialogInterface dialog, int id) {
                        dialog.cancel();
                   }
               });
            break;
        case CONFIRM_OVERWRITE_BACKUP_FILE:
            File backupFile = new File(Environment.getExternalStorageDirectory(), Utilities.DEFAULT_DATABASE_FILE);
            String messageRes = getString(R.string.backup_file_exists);
            String message = String.format(messageRes, backupFile.getAbsolutePath());

            dialogBuilder.setMessage(message)
               .setCancelable(false)
               .setPositiveButton("Yes", new DialogInterface.OnClickListener() {
                   public void onClick(DialogInterface dialog, int id) {
                       backupDatabase();
                   }
               })
               .setNegativeButton("No", new DialogInterface.OnClickListener() {
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
            TextView text = (TextView) v.findViewById(R.id.dialogText);
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
            .setPositiveButton("Yes", new DialogInterface.OnClickListener() {
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
            .setNegativeButton("No", new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int id) {
                     dialog.cancel();
                }
            });
            break;
            
            /* DELETE CONTEXT BUTTON  NOT WORKING ATM*/
  // NEED TO FIGUE THIS ONE OUT
            /* DELETE END */
            
        }

        return dialogBuilder.create();
    }
    

    private void deleteDatabase() {
        Utilities.getDatabaseFile(this).delete();
        Utilities.setDatabaseFileName(null, this);
    }

    private void backupDatabase() {
        File fileOnSDCard = new File(Environment.getExternalStorageDirectory(), Utilities.DEFAULT_DATABASE_FILE);
        File databaseFile = Utilities.getDatabaseFile(this);
        if (((UPMApplication) getApplication()).copyFile(databaseFile, fileOnSDCard, this)) {
            String message = String.format(getString(R.string.backup_complete), fileOnSDCard.getAbsolutePath());
            UIUtilities.showToast(this, message, false);
        }
    }

}
