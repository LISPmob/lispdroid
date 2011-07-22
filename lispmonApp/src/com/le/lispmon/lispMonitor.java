package com.le.lispmon;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Timer;
import java.util.TimerTask;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.os.Handler;
import android.content.DialogInterface;
import android.content.Intent;
import android.widget.CheckBox;
import android.widget.Button;
import android.widget.TextView;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;

public class lispMonitor extends Activity implements OnClickListener {
	/** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        
        /*
         * Set up the button handlers
         */
        CheckBox lispCheckBox = (CheckBox)findViewById(R.id.startStopCheckbox);
        lispCheckBox.setOnClickListener(this);
        handler = new Handler(); 
        doUpdateView = new Runnable() { 
          public void run() { 
            updateStatus();
          } 
        };
        
        Button cache = (Button) findViewById(R.id.showCacheButton);
        cache.setOnClickListener(new View.OnClickListener() {
            public void onClick(View view) {
                Intent myIntent = new Intent(view.getContext(), mapCacheActivity.class);
                startActivityForResult(myIntent, 0);
            }
        }
        );
        
        Button ping = (Button) findViewById(R.id.pingButton);
        ping.setOnClickListener(new View.OnClickListener() {
            public void onClick(View view) {
                Intent myIntent = new Intent(view.getContext(), pingActivity.class);
                startActivityForResult(myIntent, 0);
            }
        }
        );
        
        Button log = (Button) findViewById(R.id.showLogButton);
        log.setOnClickListener(new View.OnClickListener() {
            public void onClick(View view) {
                Intent myIntent = new Intent(view.getContext(), logActivity.class);
                startActivityForResult(myIntent, 0);
            }
        }
        );
        Button conf = (Button) findViewById(R.id.showConfButton);
        conf.setOnClickListener(new View.OnClickListener() {
        	public void onClick(View view) {
        		Intent myIntent = new Intent(view.getContext(), confActivity.class);
        		startActivityForResult(myIntent, 0);
        	}
        }
        );
    
        Button datacache = (Button) findViewById(R.id.showDataCacheButton);
        datacache.setOnClickListener(new View.OnClickListener() {
            public void onClick(View view) {
                Intent myIntent = new Intent(view.getContext(), dataCacheActivity.class);
                startActivityForResult(myIntent, 0);
            }
        }
        );

        Button clearcache = (Button) findViewById(R.id.showClearCacheButton);
        clearcache.setOnClickListener(new View.OnClickListener() {
            public void onClick(View view) {
                Intent myIntent = new Intent(view.getContext(), clearCacheActivity.class);
                startActivityForResult(myIntent, 0);
            }
        }
        );
        
        Log.v("lispMonitor", "Creating...");
    }
    
    Timer mUpdateTimer = null;
    @Override
    protected void onPause() {
    	super.onPause();
    	
    	Log.v("lispMonitor", "Pausing...");
    	// Stop all timers
    	mUpdateTimer.cancel();
    }
    
    @Override
    protected void onStop() {
    	super.onStop();
    	
    	Log.v("lispMonitor", "Stopping...");
    	// Stop all timers
    	mUpdateTimer.cancel();
    }
    
    @Override
    protected void onResume() {
    	super.onResume();
    	
    	Log.v("lispMonitor", "Resuming...");
    	
    	// Rebuild the timer
    	if (mUpdateTimer != null) {
    		mUpdateTimer.cancel();
    	}
    	mUpdateTimer = new Timer();
    	mUpdateTimer.scheduleAtFixedRate(new statusTask(), 0, fONCE_PER_SECOND);
    }
    
    static public String runTask(String command, String args, boolean ignoreOutput) {
    	StringBuffer output = new StringBuffer();
        Process process = null;
    	try {
    		process = new ProcessBuilder()
    		.command(command, args)
    		.redirectErrorStream(true)
    		.start();
    		InputStream in = process.getInputStream();
    		BufferedReader reader = new BufferedReader(new InputStreamReader(in));
    		String line;
    		process.waitFor();
    		if (!ignoreOutput) {
    			while ((line = reader.readLine()) != null) {
    				output.append(line);
    				output.append('\n');
    			}
    		}
    	} catch (IOException e1) {
    		return("Command Failed.");
    	} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
    	if (process != null) {
    		process.destroy();
    	}
    	return(output.toString());
    }
    
    final String infoFileLocation = "/sdcard/lispd.info";
    public void updateInfoView() {
    	final TextView statusView = (TextView) findViewById(R.id.infoView);
    	File infoFile = new File(infoFileLocation);
    	BufferedReader reader;
    	
		try {
			reader = new BufferedReader(new FileReader(infoFile));
		} catch (FileNotFoundException e) {
			statusView.setText("Info file missing.");
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
			statusView.setText("Info file read error.");
			return;
		}
    	statusView.setText(output.toString());
    }
    
    public void updateStatus() {
    	final CheckBox lispCheckBox = (CheckBox) findViewById(R.id.startStopCheckbox);
    	final TextView statusView = (TextView) findViewById(R.id.infoView);
    	
    	String lsmodOutput = runTask("/system/bin/lsmod", "", false);
    	String psOutput = runTask("/system/bin/ps", "", false);
    	if (lsmodOutput.contains("lisp") && psOutput.contains("lispd")) {
    		lispCheckBox.setText(R.string.lispRunning);
    		lispCheckBox.setChecked(true);
    		updateInfoView();
    	} else {
    		lispCheckBox.setText(R.string.lispNotRunning);
    		lispCheckBox.setChecked(false);
    		statusView.setText("");
    	}
    }
    
    public final class statusTask extends TimerTask {
    	public void run() {
    		handler.post(doUpdateView);
    	}
    }
    
    public void showMessage(String message, boolean cancelAble, final Runnable task) {

    	AlertDialog.Builder builder = new AlertDialog.Builder(this);
		builder.setTitle("Attention:");
		builder.setMessage(message)
	       .setCancelable(cancelAble)
	       .setPositiveButton("Ok", new DialogInterface.OnClickListener() {
	           public void onClick(DialogInterface dialog, int id) {
	        	   if (task != null) {
	                task.run();
	        	   } else {
	        		   dialog.dismiss();
	        	   }
	           }
	       });
		if (cancelAble) {
			builder.setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
				public void onClick(DialogInterface dialog, int id) {
					dialog.dismiss();
				}
			});
		}
		AlertDialog alert = builder.create();
		alert.show();
    }
    
    public String killLispd() {
    	String command = "/system/bin/lispmanager";
    	return(runTask(command, "stop", true));
    }
    
    public String startLispd() {
    	String command = "/system/bin/lispmanager";
    	 return(runTask(command, "start", true));
    }
    
    public void installModule() {
    	runTask("/system/bin/lispmanager", "install", true);
    }
    public void removeModule() {
    	runTask("/system/bin/lispmanager", "remove", true);
    }
    
    Handler handler;
    Runnable doUpdateView;
    //expressed in milliseconds
	private final static long fONCE_PER_SECOND = 1000;

	public void onClick(View V) {
		CheckBox lispCheckBox = (CheckBox)findViewById(R.id.startStopCheckbox);

		if (V == findViewById(R.id.startStopCheckbox)) {
			if (lispCheckBox.isChecked()) {
				installModule();
				startLispd();
				return;
			}
			showMessage("Stop the LISP service?",
					true, new Runnable() { public void run() {
						killLispd();
						removeModule();
					}
			});
		}
	}
}

