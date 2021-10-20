package main;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SecurityUtils {
    public static int keySize = 128;
    public static IvParameterSpec IV = new IvParameterSpec("q0w1e2r3t4y5y6u7".getBytes(StandardCharsets.UTF_8));
    public static String IP_ADDRESS = "127.0.0.1";
    public static int PORT = 6666;
    public static String K_ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";

    public static SecretKey generateKPrimeSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }

    public static String convertSecretKeyToString(SecretKey secretKey) {
        byte[] rawData = secretKey.getEncoded();
        return Base64.getEncoder().encodeToString(rawData);
    }

    public static SecretKey convertStringToSecretKey(String encodedKey) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    public static String convertByteArrayToString(byte[] arr) {
        return Base64.getEncoder().encodeToString(arr);
    }

    public static byte[] convertStringToByteArray(String string) {
        return Base64.getDecoder().decode(string);
    }

    public static byte[] byteArrayXOR(byte[] arr1, byte[] arr2) {
        int size;
        if (arr1.length < arr2.length)
            size = arr1.length;
        else
            size = arr2.length;
        byte[] res = new byte[size];
        int counter = -1;
        for (int i = 0; i < size; i++) {
            counter++;
            res[counter] = (byte) (arr1[counter] ^ arr2[counter]);
        }
        return res;
    }
}
