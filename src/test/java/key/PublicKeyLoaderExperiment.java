package key;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.io.*;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PublicKeyLoaderExperiment {

    private String filePathToPublicKey = "x509-public-key.pem";
    private String filePathToSelfSignedCertificate = "x509-self-signed-certificate.pem";

    private String baseURL;

    @BeforeAll
    public void init() {
        ClassLoader classLoader = this.getClass().getClassLoader();
        baseURL = classLoader.getResource("").getFile();
    }

    private File getFile(String fileName) {
        return new File(baseURL + File.separator + fileName);
    }

    @Test
    public void loadPublicKeyFromPublicKeyFile() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        FileReader fileReader = new FileReader(getFile(filePathToPublicKey));
        PemReader pemReader = new PemReader(fileReader);
        PemObject pemObject = pemReader.readPemObject();
        X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(pemObject.getContent());
        RSAPublicKey publicKey = (RSAPublicKey) factory.generatePublic(encodedKeySpec);
        System.out.println(publicKey.toString());
    }

    @Test
    public void loadPublicKeyFromCertificateFile() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, CertificateException {

        FileReader fileReader = new FileReader(getFile(filePathToSelfSignedCertificate));
        PemReader pemReader = new PemReader(fileReader);
        PemObject pemObject = pemReader.readPemObject();

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(pemObject.getContent()));

        RSAPublicKey publicKey = (RSAPublicKey) x509Certificate.getPublicKey();
        System.out.println(publicKey.toString());
    }

}
