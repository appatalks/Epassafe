package com.epassafe.upm.wrappers;

import com.epassafe.upm.wrappers.honeycomb.WrapActionBar;

public class CheckWrappers {

	public static boolean mActionBarAvailable;
	
	static {
		try {
			WrapActionBar.checkAvailable();
			mActionBarAvailable = true;
		} catch(Throwable t){
			mActionBarAvailable = false;
		}
	}
}
