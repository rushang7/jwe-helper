package org.swasth.jose.jwe.key;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PrivateKeyLoaderExperiment {

    private String filePathToPrivateKey = "x509-private-key.pem";
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
    public void loadPrivateKey() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        FileReader keyReader = new FileReader(getFile(filePathToPrivateKey));
        PemReader pemReader = new PemReader(keyReader);
        PemObject pemObject = pemReader.readPemObject();
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(pemObject.getContent());
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) factory.generatePrivate(privateKeySpec);
        System.out.println(rsaPrivateKey.toString());
    }

}
