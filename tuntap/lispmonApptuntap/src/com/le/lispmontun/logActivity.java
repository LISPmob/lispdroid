package com.le.lispmontun;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.view.View;
import android.widget.TextView;
import android.widget.ScrollView;

import java.io.*;

public class logActivity extends Activity {

	public static final String logFileLocation = "/sdcard/lispd.log";
	public static final int maxReadBytes = 200000;
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		
		setContentView(R.layout.log);
	    MyDialog = progressDialog.show( logActivity.this, " " , " Loading. Please wait ... ", true);

		new Thread(new Runnable() {
            public void run() {
               refresh();
            }
        }).start();
	}
	public void refresh() {
	    StringBuffer contents = new StringBuffer();
		
		try { 
			File tmpFile = new File(logFileLocation);
			RandomAccessFile logFile = new RandomAccessFile(tmpFile, "r");
			if (logFile.length() > maxReadBytes) {
			logFile.seek(logFile.length() - maxReadBytes);
			}
			String currentLine = logFile.readLine();
			while (currentLine != null) {
		
				if (currentLine != null) {
					contents.append(currentLine);
					contents.append('\n');
				}
				currentLine = logFile.readLine();
			}
			try {
				if (logFile != null) {
					logFile.close();
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {

		}
		
		final StringBuffer fixedContents = contents;
		mHandler.post(new Runnable() { public void run() {
			// Put the file contents into the TextView
			TextView log = (TextView) findViewById(R.id.logView); 
			log.setText(fixedContents);

			// Auto scroll to the bottom
			final ScrollView scroll = (ScrollView) findViewById(R.id.scrollView1);
			scroll.post(new Runnable() {            
				public void run() {
					scroll.fullScroll(View.FOCUS_DOWN);              
				}
			});
			MyDialog.dismiss();
		}
		}
		);
	}
	
	private Handler mHandler = new Handler();
	private progressDialog MyDialog = null;
	
	public void refreshClicked(View v) {
	    MyDialog = progressDialog.show( logActivity.this, null, null );

	    new Thread(new Runnable() {
            public void run() {
               refresh();
            }
        }).start();
	}
}
