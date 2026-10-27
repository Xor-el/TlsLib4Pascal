package org.tlslib.tests;

import android.app.Activity;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.text.InputType;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** Runs the TlsLib FPC test suite in the native library and reports it to a TestInsight server. */
public class MainActivity extends Activity {
    private static final String PrefsName = "tlslib";
    private static final String UrlKey = "baseUrl";
    private static final String DataArchive = "testdata.zip";
    private static final String LibraryName = "TlsLibAndroidTests";

    private EditText urlField;
    private TextView status;
    private Button runButton;
    private boolean libraryLoaded;
    // static: a recreated activity (rotation) must not start a second run in the same process
    private static final AtomicBoolean running = new AtomicBoolean();

    public native int nativeRun(String baseUrl, String workDir);

    @Override
    @SuppressWarnings("deprecation")
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad, pad, pad);
        // the window is drawn edge to edge on recent Android, so keep clear of the system bars
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            v.setPadding(pad + insets.getSystemWindowInsetLeft(), pad + insets.getSystemWindowInsetTop(),
                    pad + insets.getSystemWindowInsetRight(), pad + insets.getSystemWindowInsetBottom());
            return insets;
        });

        TextView title = new TextView(this);
        title.setText("TlsLib Tests");
        title.setTextSize(22);
        title.setPadding(0, 0, 0, pad);
        root.addView(title);

        urlField = new EditText(this);
        urlField.setHint("http://192.168.0.10:6789/tests");
        urlField.setSingleLine(true);
        urlField.setInputType(InputType.TYPE_TEXT_VARIATION_URI);
        urlField.setText(getSharedPreferences(PrefsName, MODE_PRIVATE).getString(UrlKey, ""));
        root.addView(urlField);

        Button saveButton = new Button(this);
        saveButton.setText("Save URL");
        saveButton.setOnClickListener(v -> {
            String url = normalise(urlField.getText().toString());
            urlField.setText(url);
            getSharedPreferences(PrefsName, MODE_PRIVATE).edit().putString(UrlKey, url).apply();
            setStatus("Saved " + url);
        });
        root.addView(saveButton);

        runButton = new Button(this);
        runButton.setText("Run tests");
        runButton.setOnClickListener(v -> startRun());
        root.addView(runButton);

        status = new TextView(this);
        status.setPadding(0, pad, 0, 0);
        root.addView(status);
        setContentView(root);

        try {
            System.loadLibrary(LibraryName);
            libraryLoaded = true;
            setStatus("Ready. Enter the TestInsight URL, save it, and tap Run tests.");
        } catch (UnsatisfiedLinkError e) {
            setStatus("Could not load " + LibraryName + ": " + e.getMessage());
            runButton.setEnabled(false);
        }

        // adb shell am start ... --ez autorun true --es url http://host:6789/tests
        if (libraryLoaded && getIntent().getBooleanExtra("autorun", false)) {
            // consumed, so a recreated activity does not run again
            getIntent().removeExtra("autorun");
            String url = getIntent().getStringExtra("url");
            if (url != null) {
                urlField.setText(normalise(url));
            }
            startRun();
        }
    }

    /** A bare host:port becomes http://host:port/tests, the base path of the IDE's server. */
    private static String normalise(String text) {
        String url = text.trim();
        if (url.isEmpty()) {
            return url;
        }
        if (!url.contains("://")) {
            url = "http://" + url;
        }
        int schemeEnd = url.indexOf("://") + 3;
        if (url.indexOf('/', schemeEnd) < 0) {
            url = url + "/tests";
        }
        return url;
    }

    private void setStatus(String message) {
        android.util.Log.i("TlsLibTests", message);
        runOnUiThread(() -> status.setText(message));
    }

    private void startRun() {
        if (!libraryLoaded) {
            return;
        }
        final String url = normalise(urlField.getText().toString());
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            setStatus("Enter an http:// or https:// TestInsight URL first.");
            return;
        }
        if (!running.compareAndSet(false, true)) {
            return;
        }
        getSharedPreferences(PrefsName, MODE_PRIVATE).edit().putString(UrlKey, url).apply();
        runButton.setEnabled(false);
        setStatus("Running against " + url);
        new Thread(() -> {
            String result;
            try {
                File work = getFilesDir();
                extractData(work);
                // adb shell am start ... --es suite TestName runs only that suite or test
                File settings = new File(work, "TestInsightSettings.ini");
                // only suite and test names may reach the ini file, so no extra keys can be injected
                String suite = getIntent().getStringExtra("suite");
                getIntent().removeExtra("suite");
                if (suite != null) {
                    suite = suite.replaceAll("[^A-Za-z0-9_.,]", "");
                }
                if (suite == null || suite.isEmpty()) {
                    settings.delete();
                } else {
                    try (OutputStream out = new FileOutputStream(settings)) {
                        out.write(("[Config]\nSuite=" + suite + "\n").getBytes("UTF-8"));
                    }
                }
                int code = nativeRun(url, work.getAbsolutePath());
                result = code == 0 ? "Finished. Results are in TestInsight." : "Run failed (code " + code + ").";
            } catch (IOException | RuntimeException e) {
                result = "Run failed: " + e;
            } finally {
                running.set(false);
            }
            final String message = result;
            android.util.Log.i("TlsLibTests", message);
            runOnUiThread(() -> {
                status.setText(message);
                runButton.setEnabled(true);
            });
        }, "tlslib-tests").start();
    }

    /** Unpacks the test data under the work folder, where the tests look for TlsLib.Tests/Data. */
    private void extractData(File work) throws IOException {
        String root = work.getCanonicalPath() + File.separator;
        try (ZipInputStream zip = new ZipInputStream(getAssets().open(DataArchive))) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                File target = new File(work, entry.getName());
                if (!target.getCanonicalPath().startsWith(root)) {
                    throw new IOException("unexpected entry " + entry.getName());
                }
                if (entry.isDirectory()) {
                    target.mkdirs();
                    continue;
                }
                target.getParentFile().mkdirs();
                try (OutputStream out = new FileOutputStream(target)) {
                    byte[] buffer = new byte[16384];
                    int read;
                    while ((read = zip.read(buffer)) > 0) {
                        out.write(buffer, 0, read);
                    }
                }
            }
        }
    }
}
