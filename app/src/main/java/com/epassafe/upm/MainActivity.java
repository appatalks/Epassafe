package com.epassafe.upm;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;

public class MainActivity extends Activity {

    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);

        // Initialize the UPM application by sending user to the entry activity
        Intent intent = new Intent(MainActivity.this, AppEntryActivity.class);
        startActivity(intent);
        finish(); // End this activity as we're just forwarding to AppEntryActivity
    }
}

