package com.epassafe.upm;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.webkit.WebSettings;
import android.webkit.WebSettings.PluginState;
import android.webkit.WebView;
import android.webkit.WebViewClient;

/* WEBVIEW Code */

public class EasterEgg extends Activity {
  
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.easteregg);
        
        WebView mainWebView = (WebView) findViewById(R.id.eastereggWebView);
        
        WebSettings webSettings = mainWebView.getSettings();
        webSettings.setJavaScriptEnabled(true);
        webSettings.setSupportZoom(true); 
        webSettings.setPluginState(PluginState.ON);
        
        mainWebView.setWebViewClient(new MyCustomWebViewClient());
        mainWebView.setScrollBarStyle(View.SCROLLBARS_INSIDE_OVERLAY);
        
        mainWebView.loadUrl("file:///android_asset/index.html");
    }
    
    private class MyCustomWebViewClient  extends WebViewClient {
        @Override
        public boolean shouldOverrideUrlLoading(WebView view, String url) {
            
        	view.loadUrl(url);
            return true;
        }
    }
} 

/* WEBVIEW CODE END */

/*
import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

	public class EasterEgg extends Activity {
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
			TextView tv = new TextView(this);
			tv.setText("Hello, Android");
		setContentView(tv);
		}
	}
	*/