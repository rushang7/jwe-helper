import com.nimbusds.jose.JOSEException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class JweRequestTest {

    int keysize = 2048;
    KeyPair keyPair;
    Map<String, Object> headers, payload;
    Map<String, String> encryptedObject;

    @BeforeAll
    public void initKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keysize);
        keyPair = keyPairGenerator.generateKeyPair();

        headers = new HashMap<>();
        headers.put("headerKey", "value");

        payload = new HashMap<>();
        payload.put("payloadKey", "payload");
    }

    @Test
    public void testEncrypt() throws JOSEException, ParseException {
        JweRequest jweRequest = new JweRequest(headers, payload);
        jweRequest.encryptRequest((RSAPublicKey) keyPair.getPublic());
        encryptedObject = jweRequest.getEncryptedObject();
        System.out.println(encryptedObject.toString());
    }

    @Test
    public void testDecrypt() throws ParseException, JOSEException {
        JweRequest jweRequest = new JweRequest(encryptedObject);
        jweRequest.decryptRequest((RSAPrivateKey) keyPair.getPrivate());
        Map<String, Object> retrievedHeader = jweRequest.getHeaders();
        Map<String, Object> retrievedPayload = jweRequest.getPayload();

        System.out.println(retrievedHeader);
        System.out.println(retrievedPayload);
    }

}