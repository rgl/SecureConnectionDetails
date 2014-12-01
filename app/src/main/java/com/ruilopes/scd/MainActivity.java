// developed by Rui Lopes (ruilopes.com). licensed under GPLv3.

package com.ruilopes.scd;

import android.annotation.TargetApi;
import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.DisplayMetrics;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

import java.io.BufferedInputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Formatter;
import java.util.Locale;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class MainActivity extends Activity {
    private Button checkButton;
    private AsyncTask checkTask;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        checkButton = (Button)findViewById(R.id.checkButton);
    }

    public void onCheckButtonClick(View view) {
        if (checkTask != null)
            return;

        checkButton.setText(R.string.checking);
        checkButton.setEnabled(false);

        checkTask = new AsyncTask<Object, Void, String>() {
            @Override
            protected String doInBackground(Object[] params) {
                StringBuilder sb = new StringBuilder();
                final Formatter formatter = new Formatter(sb, Locale.US);

                try {
                    SSLContext context = SSLContext.getInstance("TLS");
                    context.init(
                        null,
                        new TrustManager[] {
                            new X509TrustManager() {
                                @Override
                                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                                }

                                @Override
                                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                                    formatter.format("%s checkServerTrusted authType=%s\n", new Date(), authType);
                                    dumpCertificates(formatter, chain);
                                }

                                @Override
                                public X509Certificate[] getAcceptedIssuers() {
                                    return new X509Certificate[0];
                                }
                            }
                        },
                        null
                    );

                    formatter.format("%s # checking without trust manager\n", new Date());
                    check(formatter, context.getSocketFactory());

                    formatter.format("%s # checking with default trust manager\n", new Date());
                    check(formatter, null);
                }
                catch (Exception e) {
                    formatter.format(
                        "%s exception class=%s message=%s\n",
                        new Date(),
                        e.getClass(),
                        e
                    );
                }

                return sb.toString();
            }

            @Override
            protected void onPostExecute(String result) {
                checkButton.setText(R.string.check);
                checkButton.setEnabled(true);
                checkTask = null;

                String[] TO = {"rgl+cartaoalacard+android@ruilopes.com"};
                String subject = "Check Secure Connection Details Result";
                String body = result + "\n\n----\n" + getSystemInformation();

                Intent emailIntent = new Intent(Intent.ACTION_SEND);
                emailIntent.setData(Uri.parse("mailto:"));
                emailIntent.setType("text/plain");

                emailIntent.putExtra(Intent.EXTRA_EMAIL, TO);
                emailIntent.putExtra(Intent.EXTRA_SUBJECT, subject);
                emailIntent.putExtra(Intent.EXTRA_TEXT, body);

                try {
                    startActivity(Intent.createChooser(emailIntent, "Send results email..."));
                } catch (ActivityNotFoundException ex) {
                    Toast.makeText(MainActivity.this, "There is no email client installed.", Toast.LENGTH_SHORT).show();
                }
            }
        };

        checkTask.execute();
    }

    private void check(final Formatter formatter, SSLSocketFactory socketFactory) {
        for (int retryNumber = 0; retryNumber < 3; ++retryNumber) {
            if (retryNumber > 0) {
                formatter.format("%s ## retry #%d...\n", new Date(), retryNumber);
            }

            if (checkInternal(formatter, socketFactory)) {
                return;
            }

            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                formatter.format(
                    "%s exception class=%s message=%s\n",
                    new Date(),
                    e.getClass(),
                    e
                );
                return;
            }
        }
    }

    private boolean checkInternal(final Formatter formatter, SSLSocketFactory socketFactory) {
        try {
            URL url = new URL("https://www.euroticket-alacard.pt/alc/pages/login.jsf");

            formatter.format("%s connecting to %s...\n", new Date(), url);
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            formatter.format("%s connected\n", new Date());

            try {
                if (socketFactory != null) {
                    connection.setSSLSocketFactory(socketFactory);
                }

                formatter.format("%s getting input stream...\n", new Date());
                InputStream in = new BufferedInputStream(connection.getInputStream());
                formatter.format("%s got input stream\n", new Date());

                try {
                    // Handle Network Sign-On: Some Wi-Fi networks block Internet access until the
                    // user clicks through a sign-on page. Such sign-on pages are typically
                    // presented by using HTTP redirects.
                    if (!url.getHost().equals(connection.getURL().getHost())) {
                        formatter.format("%s got redirected to %s...\n", new Date(), connection.getURL());
                    }
                }
                finally {
                    in.close();
                }

                formatter.format("%s Cipher Suite %s\n", new Date(), connection.getCipherSuite());

                dumpCertificates(formatter, connection.getServerCertificates());

                return true;
            }
            finally {
                connection.disconnect();
            }
        }
        catch (Exception e) {
            formatter.format(
                "%s exception class=%s message=%s\n",
                new Date(),
                e.getClass(),
                e
            );

            return false;
        }
    }

    private void dumpCertificates(Formatter formatter, Certificate[] certificates) {
        if (certificates == null || certificates.length == 0) {
            formatter.format("%s peer didn't sent any certificate!?\n", new Date());
        }
        else {
            for (int i = 0; i < certificates.length; ++i) {
                Certificate certificate = certificates[i];

                formatter.format("%s certificate #%d type=%s class=%s\n", new Date(), i, certificate.getType(), certificate.getClass());

                if (certificate instanceof X509Certificate) {
                    X509Certificate x509 = (X509Certificate) certificate;

                    formatter.format(
                        "%s certificate #%d subject=%s issuer=%s publicKey=%s\n",
                        new Date(),
                        i,
                        x509.getSubjectX500Principal(),
                        x509.getIssuerX500Principal(),
                        x509.getPublicKey()
                    );
                }
            }
        }
    }

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    private String getSystemInformation() {
        String version;
        String packageName;

        try {
            PackageInfo packageInfo = getPackageManager().getPackageInfo(getPackageName(), 0);
            version = packageInfo.versionName;
            packageName = packageInfo.packageName;
        } catch (PackageManager.NameNotFoundException e) {
            return null;
        }

        DisplayMetrics displayMetrics;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            displayMetrics = new DisplayMetrics();
            getWindowManager().getDefaultDisplay().getRealMetrics(displayMetrics);
        } else {
            displayMetrics = getResources().getDisplayMetrics();
        }

        String systemInformation = packageName
                + "|" + version
                + "|" + Build.VERSION.RELEASE
                + "|" + Build.VERSION.SDK_INT
                + "|" + Build.BRAND
                + "|" + Build.MODEL
                + "|" + Build.MANUFACTURER
                + "|" + Build.BOARD
                + "|" + (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP ? TextUtils.join(",", Build.SUPPORTED_ABIS) : Build.CPU_ABI + "," + Build.CPU_ABI2)
                + "|" + displayMetrics.widthPixels + "x" + displayMetrics.heightPixels
                + "|" + displayMetrics.xdpi + "x" + displayMetrics.ydpi
                + "|" + displayMetrics.densityDpi
                + "|" + displayMetrics.density
                + "|" + displayMetrics.scaledDensity
                ;

        return systemInformation;
    }
}
