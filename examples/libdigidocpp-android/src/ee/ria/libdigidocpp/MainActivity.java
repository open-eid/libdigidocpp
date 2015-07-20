package ee.ria.libdigidocpp;

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import android.app.Activity;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;

public class MainActivity extends Activity {

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		try {
			ZipInputStream zis = new ZipInputStream(getResources().openRawResource(R.raw.schema));
			ZipEntry ze;
			while ((ze = zis.getNextEntry()) != null) {
				FileOutputStream out = new FileOutputStream(getCacheDir().getAbsolutePath() + "/" + ze.getName());
				byte[] buffer = new byte[1024];
				int count;
				while ((count = zis.read(buffer)) != -1) {
					out.write(buffer, 0, count);
				}
				out.close();
			}
			zis.close();

			InputStream in = getResources().openRawResource(R.raw.test);
			FileOutputStream out = new FileOutputStream(getCacheDir().getAbsolutePath() + "/test.bdoc");
			byte[] buffer = new byte[1024];
			int count;
			while ((count = in.read(buffer)) != -1) {
				out.write(buffer, 0, count);
			}
			in.close();
			out.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

		try {
			TextView content = (TextView) findViewById(R.id.content);
			System.loadLibrary("digidoc_java");
			digidoc.initJava(getCacheDir().getAbsolutePath());
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			Container doc = Container.open(getCacheDir().getAbsolutePath() + "/test.bdoc");
			content.append("DataFiles:\n");
			for(int i = 0; i < doc.dataFiles().size(); ++i) {
				DataFile dataFile = doc.dataFiles().get(i);
				content.append(dataFile.fileName() + "\n");
			}

			content.append("\nSignatures:\n");
			for(int i = 0; i < doc.signatures().size(); ++i) {
				Signature s = doc.signatures().get(i);
				content.append("ID: " + s.id() + "\n");
				X509Certificate info = (X509Certificate)
						certFactory.generateCertificate(new ByteArrayInputStream(s.signingCertificateDer()));
				content.append("Signer: " + info.getSubjectDN().toString() + "\n");
				content.append("Signing time: " + s.trustedSigningTime() + "\n");
				try {
					s.validate();
					content.append("Signature: valid\n");
				} catch (Exception e) {
					content.append("Signature: invalid\n");
				}
			}
		} catch (CertificateException e) {
			e.printStackTrace();
		}
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Handle action bar item clicks here. The action bar will
		// automatically handle clicks on the Home/Up button, so long
		// as you specify a parent activity in AndroidManifest.xml.
		int id = item.getItemId();
		if (id == R.id.action_settings) {
			return true;
		}
		return super.onOptionsItemSelected(item);
	}
}
