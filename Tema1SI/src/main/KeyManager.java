package main;

import javax.crypto.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import static main.SecurityUtils.generateKPrimeSecretKey;
import static main.SecurityUtils.keySize;

public class KeyManager {
    private static KeyManager instance = null;
    private final byte[] KBytes = new byte[keySize / 8];
    private SecretKey KPrime;

    private KeyManager() {
        initializeRandomKeys();
        System.out.println("[KeyManager] First set of random keys as bytes (K' and unencrypted K) generated successfully!...");
        try {
            KPrime = generateKPrimeSecretKey();
        } catch (NoSuchAlgorithmException ex) {
            System.err.println("[KeyManager] NoSuchAlgorithmException encountered when trying to generate SecretKey K'!...");
        } finally {
            System.out.println("[KeyManager] Converted K' to a SecretKey successfully!...");
        }
    }

    public static KeyManager getInstance() {
        if (instance == null)
            instance = new KeyManager();
        return instance;
    }

    public SecretKey getKPrime() {
        return KPrime;
    }

    private void initializeRandomKeys() {
        new SecureRandom().nextBytes(KBytes);
    }

    public String getK(Object callerObj) {
        String encryptedKString = null;
        if (callerObj instanceof NodeA) {
            System.out.println("[KeyManager] Generating encrypted K key!...");
            try {
                encryptedKString = encryptK();
            } catch (NoSuchAlgorithmException ex) {
                System.err.println("[KeyManager] NoSuchAlgorithmException found when attempting to encrypt key K!");
            } catch (BadPaddingException ex) {
                System.err.println("[KeyManager] BadPaddingException found when attempting to encrypt key K!");
            } catch (IllegalBlockSizeException ex) {
                System.err.println("[KeyManager] IllegalBlockSizeException found when attempting to encrypt key K!");
            } catch (NoSuchPaddingException ex) {
                System.err.println("[KeyManager] NoSuchPaddingException found when attempting to encrypt key K!");
            } catch (InvalidAlgorithmParameterException ex) {
                System.err.println("[KeyManager] InvalidAlgorithmParameterException found when attempting to encrypt key K!");
            } catch (InvalidKeyException ex) {
                System.err.println("[KeyManager] InvalidKeyException found when attempting to encrypt key K!");
            } finally {
                System.out.println("[KeyManager] Key K encrypted successfully using the AES/CBC/PKCS5Padding algorithm!");
            }
            System.out.println("[KeyManager] Sending encrypted key to NodeA!...");
        } else {
            System.out.println("[KeyManager] Instance of another class rather than node A tried to access SecretKey K! Access denied!");
        }
        return encryptedKString;
    }

    private String encryptK() throws NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(SecurityUtils.K_ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, KPrime, SecurityUtils.IV);
        byte[] cipherText = cipher.doFinal(KBytes);
        return Base64.getEncoder().encodeToString(cipherText);
    }
}
