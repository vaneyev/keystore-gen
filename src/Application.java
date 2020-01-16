import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;

public class Application {

	static {
		BouncyCastleProvider bcProvider = new BouncyCastleProvider();
		Security.addProvider(bcProvider);
	}

	public static void main(String[] args) {
		try (FileOutputStream fos = new FileOutputStream("esia.pfx");) {

			Instant now = Instant.now();
			Date validityBeginDate = Date.from(now);
			Date validityEndDate = Date.from(now.plus(Duration.ofDays(365 * 10)));

			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECGOST3410-2012");
			keyPairGenerator.initialize(new ECNamedCurveGenParameterSpec("Tc26-Gost-3410-12-512-paramSetA"),
					new SecureRandom());

			java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();

			ContentSigner contentSigner = new JcaContentSignerBuilder("GOST3411WITHECGOST3410-2012-512")
					.build(keyPair.getPrivate());

			X500Principal dnName = new X500Principal("CN=John Doe");
			JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName,
					BigInteger.valueOf(System.currentTimeMillis()), validityBeginDate, validityEndDate, dnName,
					keyPair.getPublic());

			X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certBuilder.build(contentSigner));

			System.out.println("===========");
			System.out.println("CERTIFICATE");
			System.out.println("===========");
			System.out.println();
			System.out.println(cert);
			System.out.println();

			System.out.println("===============");
			System.out.println("CERTIFICATE PEM");
			System.out.println("===============");
			System.out.println();
			System.out.println(Base64.toBase64String(cert.getEncoded()));
			System.out.println();

			System.out.println("===============");
			System.out.println("PRIVATE KEY PEM");
			System.out.println("===============");
			System.out.println();
			System.out.println(Base64.toBase64String(keyPair.getPrivate().getEncoded()));
			System.out.println();

			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			keyStore.load(null, null);
			Certificate[] chain = { (Certificate) cert };
			keyStore.setKeyEntry("esia", keyPair.getPrivate(), null, chain);
			keyStore.store(fos, "".toCharArray());

			Files.write(FileSystems.getDefault().getPath("esia.key"),
					("-----BEGIN PRIVATE KEY-----\n" + Base64.toBase64String(keyPair.getPrivate().getEncoded())
							+ "\n-----END PRIVATE KEY-----").getBytes(),
					StandardOpenOption.CREATE);
			Files.write(
					FileSystems.getDefault().getPath("esia.cer"), ("-----BEGIN CERTIFICATE-----\n"
							+ Base64.toBase64String(cert.getEncoded()) + "\n-----END CERTIFICATE-----").getBytes(),
					StandardOpenOption.CREATE);

		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}
}
