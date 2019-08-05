package com.epassafe.upm;

import java.util.Random;

import android.util.Log;


public class Password {	
	
	private static final String TAG = "PassGenerator";
	
	protected int length = 8;
	
	protected boolean letters = true;
	protected boolean capitalLetters = true;
	protected boolean numbers = true;
	protected boolean symbols = false;
	
	private static final String allowedLetters = "abcdefghijklmnopqrstuvwxyz";
	private static final String allowedCapitalLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	private static final String allowedNumbers = "0123456789";
	private static final String allowedSymbols = "!#$%&/()=?,;.:-_}{*][*-+/";          
	
	
	
	public void setLength(int l){
		length = l;
	}
	
	public void useLetters(boolean value){
		letters = value;
	}
	
	public void useCapitalLetters(boolean value){
		capitalLetters = value;
	}
	
	public void useNumbers(boolean value){
		numbers = value;
	}
	
	public void useSymbols(boolean value){
		symbols = value;
	}
	
	public String generate(){
		
		String password="";//generated password
		String chars = "";//we get chars from this
		String lastChar="";//last cuted char
		String letter = "";//sliced char
		Random rnd = new Random();
		
		if (letters) chars+=allowedLetters;
		if (capitalLetters) chars+=allowedCapitalLetters;
		if (numbers) chars+=allowedNumbers;
		if (symbols) chars+=allowedSymbols;
		
		Log.d(TAG, "Chars: " +  chars);
		Log.d(TAG, "Num. chars: "+String.valueOf(chars.length()));
		
		if (chars.length() == 0){
			Log.d(TAG, "No chars, so return null string");
			return "";
		}
		
		
		while(password.length()<length){		
			
			int pos = rnd.nextInt(chars.length());			
			letter = chars.substring(pos, pos+1);
			
			Log.d(TAG, String.valueOf(pos)+"->"+letter);			
			
			if (letter.equals(lastChar)){
				Log.d(TAG, letter+" is repeated, skip");
				continue;
			}else lastChar = letter;
			
			
			password += letter;
			
		}
		
		
		return password;
	}
	
}
