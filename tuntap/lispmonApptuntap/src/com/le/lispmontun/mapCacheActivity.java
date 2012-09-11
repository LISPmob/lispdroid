package com.le.lispmontun;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

public class mapCacheActivity extends Activity {
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.cache); 
		refresh();
	}
	
	private void refresh() {
		TextView t = (TextView) findViewById(R.id.cacheView);
		String cacheContents = lispMonitor.runTask("/system/bin/lispconf", "-xcache", false);
		t.setText(cacheContents);
	}
	public void refreshClicked(View v) {
		refresh();
	}
}
