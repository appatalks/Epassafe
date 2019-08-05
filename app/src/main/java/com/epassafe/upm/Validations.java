package com.epassafe.upm;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Validations {
	
	/**
	 * Checks if a string is a integer
	 * 
	 * @param	(String)n
	 * @return	(boolean)
	 */
	public static boolean isInteger(String n){
		Pattern pattern = Pattern.compile( "\\d+" );
		Matcher matcher = pattern.matcher(n);
		return matcher.matches();		
	}

}
