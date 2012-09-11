package com.le.lispmon;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

public class dataCacheActivity extends Activity {
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.datacache); 
		refresh();
	}
	
	private void refresh() {
		TextView t = (TextView) findViewById(R.id.datacacheView);
		String datacacheContents = lispMonitor.runTask("/system/bin/lispconf", "-xdcache", false);
		t.setText(datacacheContents);
	}
	public void refreshdataCacheClicked(View v) {
		refresh();
	}
}
