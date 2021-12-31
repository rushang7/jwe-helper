package org.swasth.jose.jwe.experiment;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class Jose4JExperiment {

    int numberOfKeys = 3, keysize = 2048;
    KeyPair[] keys;

    @BeforeAll
    public void initKeys() throws NoSuchAlgorithmException {
        keys = new KeyPair[numberOfKeys];
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keysize);
        for (int i = 0; i < numberOfKeys; i++) {
            keys[i] = keyPairGenerator.generateKeyPair();
        }
    }

    @Test
    public void testJweCompactSerialization() throws JoseException {
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setPayload("Hello World!");
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);

        jwe.setKey(keys[0].getPublic());
        jwe.setHeader("asd", "qwe");

        String serializedJwe = jwe.getCompactSerialization();

        System.out.println("Serialized Encrypted JWE: " + serializedJwe);

        System.out.println("JWE : " + jwe);

        jwe = new JsonWebEncryption();
        jwe.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT,
                KeyManagementAlgorithmIdentifiers.RSA_OAEP_256));
        jwe.setContentEncryptionAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.PERMIT,
                ContentEncryptionAlgorithmIdentifiers.AES_256_GCM));
        jwe.setKey(keys[0].getPrivate());
        jwe.setCompactSerialization(serializedJwe);
        System.out.println("Payload: " + jwe.getPayload());
    }

}
