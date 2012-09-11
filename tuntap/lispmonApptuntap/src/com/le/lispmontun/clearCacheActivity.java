package com.le.lispmontun;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

public class clearCacheActivity extends Activity {
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.clearcache); 
		refresh();
	}
	
	private void refresh() {
		TextView t = (TextView) findViewById(R.id.clearcacheView);
		String clearcacheContents = lispMonitor.runTask("/system/bin/lispconf", "-c", false);
		t.setText(clearcacheContents);
	}
	public void refreshdataCacheClicked(View v) {
		refresh();
	}
}
