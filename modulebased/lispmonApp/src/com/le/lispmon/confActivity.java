package com.le.lispmon;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

public class confActivity extends Activity {
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.conf); 
		refresh();
	}
	final String confFileLocation = "/sdcard/lispd.conf";
	
	private void refresh() {
		final TextView statusView = (TextView) findViewById(R.id.confView);
    	File infoFile = new File(confFileLocation);
    	BufferedReader reader;
    	
    	
		try {
			reader = new BufferedReader(new FileReader(infoFile));
		} catch (FileNotFoundException e) {
			statusView.setText("Configuration file missing.\nPlease Go To \"Update LISP Configuration\" screen to input configuration.\n");
			return;
		}
    	String line;
    	StringBuffer output = new StringBuffer();
    	
    	try {
			while ((line = reader.readLine()) != null) {
				output.append(line);
				output.append("\n");
			}
		} catch (IOException e) {
			statusView.setText("Configuration file read error.");
			return;
		}
    	statusView.setText(output.toString());
	}
	
}
