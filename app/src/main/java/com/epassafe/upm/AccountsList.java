/*
 * Universal Password Manager
 \* Copyright (c) 2010-2011 Adrian Smith - MODDIFIED By Steven Bennett for UPM - Epassafe
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

import android.app.ListActivity;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.Context;
import android.content.Intent;
import android.content.ClipboardManager;
import android.os.Bundle;
import android.os.PersistableBundle;
import android.view.ContextMenu;
import android.view.ContextMenu.ContextMenuInfo;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.WindowManager.LayoutParams;
import android.widget.AdapterView.AdapterContextMenuInfo;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import com.epassafe.upm.database.AccountInformation;
import com.epassafe.upm.database.PasswordDatabase;

import java.util.Timer;
import java.util.TimerTask;

@SuppressWarnings("deprecation")
public class AccountsList extends ListActivity {

    public static AccountInformation account;
    private int editAccountResultCode = 0;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);       
        
        /* Time Lockout after 10 mins */
        getWindow().addFlags(LayoutParams.FLAG_KEEP_SCREEN_ON);
        
        Timer timer = new Timer();
        timer.schedule(new TimerTask() {

           public void run() {

           	Intent i = new Intent(AccountsList.this, AppEntryActivity.class);
            i.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
            startActivity(i);
            finish();
            return;

           }

        }, 3600000);
        /* Time Lockout END */
    }

    @Override
    public void onCreateContextMenu(ContextMenu menu, View v, ContextMenuInfo menuInfo) {
        super.onCreateContextMenu(menu, v, menuInfo);
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.account_context_menu, menu);
    }
    
    @Override
    public boolean onContextItemSelected(MenuItem item) {
        AdapterContextMenuInfo info = (AdapterContextMenuInfo) item.getMenuInfo();
        switch (item.getItemId()) {
        case R.id.edit_account:
            editAccount(getAccount(info.targetView));
            return true;
        case R.id.copy_password:
            setClipboardText(getPassword(getAccount(info.targetView)));
            return true;
        }
        return super.onContextItemSelected(item);
    }

    // Android 13 New Feature - Clipboard Sensitive Data
    private void setClipboardText(String text) {
        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData clip = ClipData.newPlainText("Password", text.toString());
        PersistableBundle extras = new PersistableBundle();
        extras.putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true);
        clip.getDescription().setExtras(extras);
        clipboard.setPrimaryClip(clip);
    }

    private AccountInformation getAccount(View listviewItem) {
        return getPasswordDatabase().getAccount(((TextView) listviewItem).getText().toString());
    }

    private String getPassword(AccountInformation account) {
        return new String(account.getPassword());
    }

    private void viewAccount(AccountInformation ai) {
        // Pass the AccountInformation object o the AccountDetails Activity by
        // way of a static variable on that class. I really don't like this but
        // it seems like the best way of doing it
        // @see http://developer.android.com/guide/appendix/faq/framework.html#3
        ViewAccountDetails.account = ai;

        Intent i = new Intent(AccountsList.this, ViewAccountDetails.class);
        startActivityForResult(i, ViewAccountDetails.VIEW_ACCOUNT_REQUEST_CODE);
    }

    private void editAccount(AccountInformation ai) {
        if (ai != null) {
                Intent i = new Intent(AccountsList.this, AddEditAccount.class);
                i.putExtra(AddEditAccount.MODE, AddEditAccount.EDIT_MODE);
                i.putExtra(AddEditAccount.ACCOUNT_TO_EDIT, ai.getAccountName());
                startActivityForResult(i, AddEditAccount.EDIT_ACCOUNT_REQUEST_CODE);
            }
        }

    @Override
    protected void onListItemClick(ListView l, View v, int position, long id) {
        // Get the name of the account the user selected
        TextView itemSelected = (TextView) v;
        viewAccount(getPasswordDatabase().getAccount(itemSelected.getText().toString()));
    }

    protected PasswordDatabase getPasswordDatabase() {
        return ((UPMApplication) getApplication()).getPasswordDatabase();
    }

}
