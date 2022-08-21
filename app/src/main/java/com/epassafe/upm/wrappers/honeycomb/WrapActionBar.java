package com.epassafe.upm.wrappers.honeycomb;

import android.app.ActionBar;
import android.app.Activity;
import android.view.MenuItem;

public class WrapActionBar {
	private ActionBar mInstance;

	static {
		try {
			Class.forName("android.app.ActionBar");
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}

	/* calling here forces class initialization */
	public static void checkAvailable() {
	}

	public WrapActionBar(Activity a) {
		mInstance = a.getActionBar();
	}

	public void setDisplayHomeAsUpEnabled(boolean b) {
		if (mInstance != null) {
			mInstance.setDisplayHomeAsUpEnabled(b);
		}
	}

	public void setHomeButtonEnabled(boolean b) {
		if (mInstance != null) {
			mInstance.setHomeButtonEnabled(b);
		}
	}

	// show an icon in the actionbar if there is room for it.
	public static void showIfRoom(MenuItem item1) {
		item1.setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);
	}

	public static void invalidateOptionsMenu(Activity a) {
		a.invalidateOptionsMenu();
	}
}
