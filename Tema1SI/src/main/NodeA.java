package main;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.Scanner;

import static main.SecurityUtils.*;

public class NodeA {
    private final Scanner scanner = new Scanner(System.in);
    private SecretKey KPrime;
    private Socket clientSocket;
    private PrintWriter out;
    private BufferedReader in;
    private String encryptedK;
    private byte[] decryptedK;

    public static void main(String[] args) {
        NodeA A = new NodeA();
        A.startConnection(SecurityUtils.IP_ADDRESS, SecurityUtils.PORT);
        A.beginCommunication();
    }

    public void startConnection(String ip, int port) {
        try {
            clientSocket = new Socket(ip, port);
            out = new PrintWriter(clientSocket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        } catch (UnknownHostException ex) {
            System.err.println("[NodeB] Unknown Host Exception caught when attempting to start connection!");
        } catch (IOException ex) {
            System.err.println("[NodeB] IOException caught when attempting to start connection!");
        } finally {
            System.out.println("[NodeB] Client connection established!");
        }
    }

    public void beginCommunication() {
        String message;
        boolean isDone = false;
        System.out.println("[NodeA-SETUP] Instantiating of KeyManager and sending KPrime key to NodeB!...");
        KPrime = KeyManager.getInstance().getKPrime();
        out.println(convertSecretKeyToString(KPrime));
        System.out.println("\n======================\n");
        while (!isDone) {
            System.out.println("[NodeA] Please type in your command!...");
            out.println(KeyManager.getInstance().getKPrime());
            message = scanner.nextLine();
            switch (message.toUpperCase()) {
                case "EXIT":
                    System.out.println("[NodeA] Quitting connection with NodeB!...");
                    out.println(message.toUpperCase());
                    isDone = true;
                    break;
                case "ECB":
                    System.out.println("[NodeA] ECB operation mode has been chosen!...");
                    out.println(message.toUpperCase());
                    System.out.println("[NodeA] Requesting encrypted K key from KeyManager!...");
                    if (encryptedK == null)
                        encryptedK = KeyManager.getInstance().getK(this);
                    System.out.println("[NodeA] Encrypted K key acquired successfully!...");
                    System.out.println("[NodeA] Sending encrypted K key to NodeB!...");
                    out.println(encryptedK);
                    System.out.println("[NodeA] The encrypted K key is: " + encryptedK);
                    attemptKDecryption();
                    String responseECB = null;
                    try {
                        responseECB = in.readLine();
                    } catch (IOException ex) {
                        System.err.println("[NodeA] IOException caught when trying to begin communication!");
                    }
                    assert responseECB != null;
                    if (!responseECB.equals("OK")) {
                        System.err.println("[NodeA] Something went wrong!");
                        break;
                    }
                    System.out.println("[NodeA] Received the signal from nodeB that the communication is ready to begin!");
                    System.out.println("\n======================\n");

                    // ECB ENCRYPTION IMPLEMENTATION

                    Key aesKeyECB = new SecretKeySpec(decryptedK, "AES");
                    Cipher cipherECB = null;
                    try {
                        cipherECB = Cipher.getInstance("AES");
                        cipherECB.init(Cipher.ENCRYPT_MODE, aesKeyECB);
                    } catch (NoSuchAlgorithmException ex) {
                        System.err.println("[NodeA] NoSuchAlgorithmException found when attempting to encrypt file!");
                    } catch (NoSuchPaddingException ex) {
                        System.err.println("[NodeA] NoSuchPaddingException found when attempting to encrypt file!");
                    } catch (InvalidKeyException ex) {
                        System.err.println("[NodeA] InvalidKeyException found when attempting to encrypt file!");
                    }
                    int cypherBlockSizeECB = keySize / 8;
                    int counterECB = 0;
                    byte[][] newArrayECB = new byte[cypherBlockSizeECB][cypherBlockSizeECB];
                    File file = new File("plaintextECB.txt");
                    byte[] contentECB = null;
                    try {
                        contentECB = Files.readAllBytes(file.toPath());
                    } catch (IOException ex) {
                        System.err.println("[NodeA] IOException caught when trying to convert file into bytes!...");
                    }

                    for (int i = 0; i < Objects.requireNonNull(contentECB).length - cypherBlockSizeECB + 1; i += cypherBlockSizeECB)
                        newArrayECB[counterECB++] = Arrays.copyOfRange(contentECB, i, i + cypherBlockSizeECB);
                    if (contentECB.length % cypherBlockSizeECB != 0)
                        newArrayECB[counterECB++] = Arrays.copyOfRange(contentECB, contentECB.length - contentECB.length % cypherBlockSizeECB, contentECB.length);
                    System.out.println("[NodeA] We have " + (counterECB - 1) + " 16-bytes blocks! We encrypt each of them!...");
                    for (int i = 0; i < counterECB; i++) {
                        try {
                            assert cipherECB != null;
                            newArrayECB[i] = cipherECB.doFinal(newArrayECB[i]);
                        } catch (BadPaddingException ex) {
                            System.err.println("[NodeA] BadPaddingException found when attempting to encrypt file!");
                        } catch (IllegalBlockSizeException ex) {
                            System.err.println("[NodeA] IllegalBlockSizeException found when attempting to encrypt file!");
                        }
                    }
                    out.println(counterECB);
                    for (int i = 0; i < counterECB; i++) {
                        out.println(convertByteArrayToString(newArrayECB[i]));
                    }
                    System.out.println("[NodeA] The encoded byte blocks have been sent!...");
                    String feedback = null;
                    try {
                        feedback = in.readLine();
                    } catch (IOException ex) {
                        System.err.println("[NodeA] IOException found when getting decryption feedback!...");
                    }
                    assert feedback != null;
                    if (feedback.equals("OK")) {
                        System.out.println("[NodeA] Decrypted file created successfully! Quitting!...");
                    } else {
                        System.out.println("[NodeA] Something went wrong! Quitting!...");
                    }
                    isDone = true;
                    break;
                case "CFB":
                    System.out.println("[NodeA] CFB operation mode has been chosen!...");
                    out.println(message.toUpperCase());
                    System.out.println("[NodeA] Requesting encrypted K key from KeyManager!...");
                    if (encryptedK == null)
                        encryptedK = KeyManager.getInstance().getK(this);
                    System.out.println("[NodeA] Encrypted K key acquired successfully!...");
                    System.out.println("[NodeA] Sending encrypted K key to NodeB!...");
                    out.println(encryptedK);
                    System.out.println("[NodeA] The encrypted K key is: " + encryptedK);
                    System.out.println("[NodeA] Decrypting K key!...");
                    attemptKDecryption();
                    String responseCFB = null;
                    try {
                        responseCFB = in.readLine();
                    } catch (IOException ex) {
                        System.err.println("[NodeA] IOException caught when trying to begin communication!");
                    }
                    assert responseCFB != null;
                    if (!responseCFB.equals("OK")) {
                        System.err.println("[NodeA] Something went wrong!");
                        break;
                    }
                    System.out.println("[NodeA] Received the signal from nodeB that the communication is ready to begin!");
                    System.out.println("\n======================\n");

                    // CFB ENCRYPTION IMPLEMENTATION

                    Key aesKeyCFB = new SecretKeySpec(decryptedK, "AES");
                    Cipher cipherCFB = null;
                    try {
                        cipherCFB = Cipher.getInstance("AES");
                        cipherCFB.init(Cipher.ENCRYPT_MODE, aesKeyCFB);
                    } catch (NoSuchAlgorithmException ex) {
                        System.err.println("[NodeA] NoSuchAlgorithmException found when attempting to encrypt file!");
                    } catch (NoSuchPaddingException ex) {
                        System.err.println("[NodeA] NoSuchPaddingException found when attempting to encrypt file!");
                    } catch (InvalidKeyException ex) {
                        System.err.println("[NodeA] InvalidKeyException found when attempting to encrypt file!");
                    }
                    int cypherBlockSizeCFB = keySize / 8;
                    int counterCFB = 0;
                    byte[][] newArrayCFB = new byte[cypherBlockSizeCFB][cypherBlockSizeCFB];
                    File fileCFB = new File("plaintextCFB.txt");
                    byte[] contentCFB = null;
                    try {
                        contentCFB = Files.readAllBytes(fileCFB.toPath());
                    } catch (IOException ex) {
                        System.err.println("[NodeA] IOException caught when trying to convert file into bytes!...");
                    }
                    for (int i = 0; i < Objects.requireNonNull(contentCFB).length - cypherBlockSizeCFB + 1; i += cypherBlockSizeCFB)
                        newArrayCFB[counterCFB++] = Arrays.copyOfRange(contentCFB, i, i + cypherBlockSizeCFB);
                    if (contentCFB.length % cypherBlockSizeCFB != 0)
                        newArrayCFB[counterCFB++] = Arrays.copyOfRange(contentCFB, contentCFB.length - contentCFB.length % cypherBlockSizeCFB, contentCFB.length);
                    System.out.println("[NodeA] We have " + (counterCFB - 1) + " 16-bytes blocks! We encrypt each of them!...");
                    out.println(counterCFB);
                    byte[] startBlock = IV.getIV();
                    for (int i = 0; i < counterCFB; i++) {
                        try {
                            assert cipherCFB != null;
                            byte[] currentResultedEncryptedBlock = cipherCFB.doFinal(startBlock);
                            byte[] levelBlock = byteArrayXOR(currentResultedEncryptedBlock, newArrayCFB[i]);
                            out.println(convertByteArrayToString(levelBlock));
                            startBlock = levelBlock;
                        } catch (BadPaddingException ex) {
                            System.err.println("[NodeA] BadPaddingException found when attempting to encrypt file!");
                        } catch (IllegalBlockSizeException ex) {
                            System.err.println("[NodeA] IllegalBlockSizeException found when attempting to encrypt file!");
                        }
                    }
                    System.out.println("[NodeA] The encoded byte blocks have been sent!...");
                    String feedbackCFB = null;
                    try {
                        feedbackCFB = in.readLine();
                    } catch (IOException ex) {
                        System.err.println("[NodeA] IOException found when getting decryption feedback!...");
                    }
                    assert feedbackCFB != null;
                    if (feedbackCFB.equals("OK")) {
                        System.out.println("[NodeA] Decrypted file created successfully! Quitting!...");
                    } else {
                        System.out.println("[NodeA] Something went wrong! Quitting!...");
                    }
                    isDone = true;
                    break;
                default:
                    System.out.println("[NodeA] Command not recognized! Try again!...");
            }
        }
        stopConnection();
    }

    public void stopConnection() {
        try {
            in.close();
            out.close();
            clientSocket.close();
        } catch (IOException ex) {
            System.err.println("[NodeB] IOException caught when attempting to close connection!");
        }
    }

    private void attemptKDecryption() {
        try {
            decryptK();
        } catch (NoSuchAlgorithmException ex) {
            System.err.println("[NodeA] NoSuchAlgorithmException found when attempting to decrypt key K!");
        } catch (BadPaddingException ex) {
            System.err.println("[NodeA] BadPaddingException found when attempting to decrypt key K!");
        } catch (IllegalBlockSizeException ex) {
            System.err.println("[NodeA] IllegalBlockSizeException found when attempting to decrypt key K!");
        } catch (NoSuchPaddingException ex) {
            System.err.println("[NodeA] NoSuchPaddingException found when attempting to decrypt key K!");
        } catch (InvalidAlgorithmParameterException ex) {
            System.err.println("[NodeA] InvalidAlgorithmParameterException found when attempting to decrypt key K!");
        } catch (InvalidKeyException ex) {
            System.err.println("[NodeA] InvalidKeyException found when attempting to decrypt key K!");
        } finally {
            System.out.println("[NodeA] Key K decrypted successfully!...");
        }
    }

    private void decryptK() throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(SecurityUtils.K_ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, KPrime, SecurityUtils.IV);
        decryptedK = cipher.doFinal(Base64.getDecoder().decode(encryptedK));
    }
}
