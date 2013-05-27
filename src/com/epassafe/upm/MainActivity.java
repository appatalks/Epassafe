package com.epassafe.upm;
 
import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TextView;

 
public abstract class MainActivity extends Activity implements OnClickListener{
     
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
         
        final Button countButton = (Button) findViewById(R.id.add);
         
        countButton.setOnClickListener(new OnClickListener() {
             
            public void onClick(View v) {
				
				Intent intent = new Intent(MainActivity.this,AddEditAccount.class);
				MainActivity.this.startActivity(intent);
            }
        });
         
    }
}