package com.epassafe.upm;


import android.content.Context;
import android.os.Bundle;
import android.preference.EditTextPreference;
import android.preference.Preference;
import android.preference.Preference.OnPreferenceChangeListener;
import android.preference.PreferenceActivity;
import android.preference.PreferenceManager;
import android.util.Log;
import android.widget.Toast;

public class GenPrefs extends PreferenceActivity implements OnPreferenceChangeListener{
	
	private static final String TAG = "PassGenerator";
	
	private static final String OPTION_LENGTH = "option_length";
	private static int OPTION_LENGTH_DEFAULT = 8;
	private static int OPTION_LENGTH_MIN = 4;
	private static int OPTION_LENGTH_MAX = 20;
	
	private static final String OPTION_LETTERS = "option_letters";
	private static final boolean OPTION_LETTERS_DEFAULT = true;
	
	private static final String OPTION_CAPITAL_LETTERS = "option_capital_letters";
	private static final boolean OPTION_CAPITAL_LETTERS_DEFAULT = true;
	
	private static final String OPTION_NUMBERS = "option_numbers";
	private static final boolean OPTION_NUMBERS_DEFAULT = true;
	
	private static final String OPTION_SYMBOLS = "option_symbols";
	private static final boolean OPTION_SYMBOLS_DEFAULT = true;
	
	private static final String OPTION_CLIPBOARD = "option_clipboard";
	private static final boolean OPTION_CLIPBOARD_DEFAULT = false;
	

	@SuppressWarnings("deprecation")
	@Override
	protected void onCreate (Bundle savedInstanceState){
		super.onCreate(savedInstanceState);
		addPreferencesFromResource(R.xml.settings);	
			
		EditTextPreference length = (EditTextPreference) findPreference(OPTION_LENGTH);
		length.setOnPreferenceChangeListener(this);		
		
		int iLength=getLength(this);
		updateOptionLength(String.valueOf(iLength));
	}
		
	@Override
	public boolean onPreferenceChange(Preference preference, Object newValue) {
				
		if (preference.getKey().equals(OPTION_LENGTH)){
			if (checkOptionLength((String) newValue)){
				updateOptionLength((String) newValue);
				return true;
			}
		}	
		
		return false;
	}
	
	public boolean checkOptionLength(String sLength){
		
		boolean error = false;
		
		if (sLength.equals("")) return false;
		
		if (!Validations.isInteger(sLength)){
			error = true;
			Log.d(TAG, sLength+" has not numeric chars");
		}
		
		if (!error){
			int iLength = Integer.valueOf(sLength);
			
			if ((iLength < OPTION_LENGTH_MIN) || (iLength > OPTION_LENGTH_MAX)){
				error = true;
				Log.d(TAG, sLength+" is not a valid number");
			}
		}
		
		if (error){		
			String text = getString(R.string.option_length_not_valid);
			text = text.replace("#OPTION_LENGTH_MIN#",String.valueOf(OPTION_LENGTH_MIN));
			text = text.replace("#OPTION_LENGTH_MAX#",String.valueOf(OPTION_LENGTH_MAX));
			Toast.makeText(this, text, Toast.LENGTH_LONG).show();
		}
		
		return !error;
	}
	
	public void updateOptionLength(String slength){
		@SuppressWarnings("deprecation")
		EditTextPreference length = (EditTextPreference) findPreference(OPTION_LENGTH);	
		length.setSummary(String.valueOf(slength));
	}
	
	
	
	//methods to get current values of options
	
	public static int getLength(Context context){
		
		String slength = PreferenceManager.getDefaultSharedPreferences(context)
			.getString(OPTION_LENGTH, "");			
		
		if (Validations.isInteger(slength) && !slength.equals("")){
			return Integer.parseInt(slength);
		}else{
			return OPTION_LENGTH_DEFAULT;
		}			
	}
	
	public static boolean isIncludeLetters(Context context){
		return PreferenceManager.getDefaultSharedPreferences(context)
				.getBoolean(OPTION_LETTERS, OPTION_LETTERS_DEFAULT);
	}
	
	public static boolean isIncludeCapitalLetters(Context context){
		return PreferenceManager.getDefaultSharedPreferences(context)
				.getBoolean(OPTION_CAPITAL_LETTERS, OPTION_CAPITAL_LETTERS_DEFAULT);
	}
	
	public static boolean isIncludeNumbers(Context context){
		return PreferenceManager.getDefaultSharedPreferences(context)
				.getBoolean(OPTION_NUMBERS, OPTION_NUMBERS_DEFAULT);
	}
	
	public static boolean isIncludeSymbols(Context context){
		return PreferenceManager.getDefaultSharedPreferences(context)
				.getBoolean(OPTION_SYMBOLS, OPTION_SYMBOLS_DEFAULT);
	}	
	
	public static boolean isEnabledClipboard(Context context){
		return PreferenceManager.getDefaultSharedPreferences(context)
			.getBoolean(OPTION_CLIPBOARD, OPTION_CLIPBOARD_DEFAULT);
	}
	 
}
