package main;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static main.SecurityUtils.*;

public class NodeB {
    private SecretKey KPrime;
    private ServerSocket serverSocket;
    private Socket clientSocket;
    private PrintWriter out;
    private BufferedReader in;
    private String encryptedK;
    private byte[] decryptedK;

    public static void main(String[] args) {
        NodeB B = new NodeB();
        B.start(SecurityUtils.PORT);
    }

    public void start(int port) {
        try {
            serverSocket = new ServerSocket(port);
            clientSocket = serverSocket.accept();
            System.out.println("[NodeB] Connection with client NodeA successful!...");
            out = new PrintWriter(clientSocket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            System.out.println("[NodeB-SETUP] Receiving KPrime key from NodeA!...");
            KPrime = convertStringToSecretKey(in.readLine());
            System.out.println("\n======================\n");
            String inputLine;
            boolean isDone = false;
            while (!isDone) {
                inputLine = in.readLine();
                switch (inputLine) {
                    case "EXIT":
                        System.out.println("[NodeB] NodeA requested quitting!...");
                        out.println("exit");
                        isDone = true;
                        break;
                    case "ECB":
                        System.out.println("[NodeB] NodeA chose the ECB operation mode!...");
                        encryptedK = in.readLine();
                        System.out.println("[NodeB] Encrypted K key received successfully!...");
                        System.out.println("[NodeB] The encrypted K key is: " + encryptedK);
                        attemptKDecryption();
                        out.println("OK");
                        System.out.println("[NodeB] Signaling to NodeA the communication is ready to begin!...");
                        System.out.println("\n======================\n");

                        // ECB DECRYPTION IMPLEMENTATION

                        Key aesKeyECB = new SecretKeySpec(decryptedK, "AES");
                        Cipher cipherECB = null;
                        try {
                            cipherECB = Cipher.getInstance("AES");
                            cipherECB.init(Cipher.DECRYPT_MODE, aesKeyECB);
                        } catch (NoSuchAlgorithmException ex) {
                            System.err.println("[NodeB] NoSuchAlgorithmException found when attempting to decrypt file!");
                        } catch (NoSuchPaddingException ex) {
                            System.err.println("[NodeB] NoSuchPaddingException found when attempting to decrypt file!");
                        } catch (InvalidKeyException ex) {
                            System.err.println("[NodeB] InvalidKeyException found when attempting to decrypt file!");
                        }
                        int cypherBlockSizeECB = keySize / 8;
                        int counterECB = Integer.parseInt(in.readLine());
                        byte[][] encodedArrayECB = new byte[cypherBlockSizeECB][cypherBlockSizeECB];
                        ByteArrayOutputStream outputStreamECB = new ByteArrayOutputStream();
                        for (int i = 0; i < counterECB; i++) {
                            encodedArrayECB[i] = convertStringToByteArray(in.readLine());
                            try {
                                assert cipherECB != null;
                                encodedArrayECB[i] = cipherECB.doFinal(encodedArrayECB[i]);
                            } catch (BadPaddingException ex) {
                                System.err.println("[NodeB] BadPaddingException found when attempting to decrypt file!");
                            } catch (IllegalBlockSizeException ex) {
                                System.err.println("[NodeB] IllegalBlockSizeException found when attempting to decrypt file!");
                            }
                            outputStreamECB.write(encodedArrayECB[i]);
                        }
                        System.out.println("[NodeB] The encoded byte blocks have been received and decrypted!...");
                        byte[] plainBytesECB = outputStreamECB.toByteArray();
                        try (FileOutputStream fosECB = new FileOutputStream("decodedplaintextECB.txt")) {
                            fosECB.write(plainBytesECB);
                        }
                        out.println("OK");
                        System.out.println("[NodeB] The decrypted file has been created successfully! Quitting!...");
                        isDone = true;
                        break;
                    case "CFB":
                        System.out.println("[NodeB] NodeA chose the CFB operation mode!...");
                        encryptedK = in.readLine();
                        System.out.println("[NodeB] Encrypted K key received successfully!...");
                        System.out.println("[NodeB] The encrypted K key is: " + encryptedK);
                        attemptKDecryption();
                        out.println("OK");
                        System.out.println("[NodeB] Signaling to NodeA the communication is ready to begin!");
                        System.out.println("\n======================\n");

                        // CFB DECRYPTION IMPLEMENTATION

                        Key aesKeyCFB = new SecretKeySpec(decryptedK, "AES");
                        Cipher cipherCFB = null;
                        try {
                            cipherCFB = Cipher.getInstance("AES");
                            cipherCFB.init(Cipher.ENCRYPT_MODE, aesKeyCFB);
                        } catch (NoSuchAlgorithmException ex) {
                            System.err.println("[NodeB] NoSuchAlgorithmException found when attempting to decrypt file!");
                        } catch (NoSuchPaddingException ex) {
                            System.err.println("[NodeB] NoSuchPaddingException found when attempting to decrypt file!");
                        } catch (InvalidKeyException ex) {
                            System.err.println("[NodeB] InvalidKeyException found when attempting to decrypt file!");
                        }
                        int counterCFB = Integer.parseInt(in.readLine());
                        ByteArrayOutputStream outputStreamCFB = new ByteArrayOutputStream();
                        byte[] startBlock = IV.getIV();
                        for (int i = 0; i < counterCFB; i++) {
                            try {
                                assert cipherCFB != null;
                                byte[] currentCypherText = cipherCFB.doFinal(startBlock);
                                byte[] cypherTextBlock = convertStringToByteArray(in.readLine());
                                byte[] levelBlock = byteArrayXOR(currentCypherText, cypherTextBlock);
                                outputStreamCFB.write(levelBlock);
                                startBlock = cypherTextBlock;
                            } catch (BadPaddingException ex) {
                                System.err.println("[NodeA] BadPaddingException found when attempting to encrypt file!");
                            } catch (IllegalBlockSizeException ex) {
                                System.err.println("[NodeA] IllegalBlockSizeException found when attempting to encrypt file!");
                            }
                        }
                        System.out.println("[NodeB] The encoded byte blocks have been received and decrypted!...");
                        byte[] plainBytesCFB = outputStreamCFB.toByteArray();
                        try (FileOutputStream fosECB = new FileOutputStream("decodedplaintextCFB.txt")) {
                            fosECB.write(plainBytesCFB);
                        }
                        out.println("OK");
                        System.out.println("[NodeB] The decrypted file has been created successfully! Quitting!...");
                        isDone = true;
                        break;
                }
            }
            stop();
        } catch (IOException ex) {
            System.err.println("[NodeB] IOException caught when trying to start server!");
        }
    }

    public void stop() {
        try {
            in.close();
            out.close();
            clientSocket.close();
            serverSocket.close();
        } catch (IOException ex) {
            System.err.println("[NodeB] IOException caught when trying to stop server!");
        }
    }

    private void attemptKDecryption() {
        try {
            decryptK();
        } catch (NoSuchAlgorithmException ex) {
            System.err.println("[NodeB] NoSuchAlgorithmException found when attempting to decrypt key K!");
        } catch (BadPaddingException ex) {
            System.err.println("[NodeB] BadPaddingException found when attempting to decrypt key K!");
        } catch (IllegalBlockSizeException ex) {
            System.err.println("[NodeB] IllegalBlockSizeException found when attempting to decrypt key K!");
        } catch (NoSuchPaddingException ex) {
            System.err.println("[NodeB] NoSuchPaddingException found when attempting to decrypt key K!");
        } catch (InvalidAlgorithmParameterException ex) {
            System.err.println("[NodeB] InvalidAlgorithmParameterException found when attempting to decrypt key K!");
        } catch (InvalidKeyException ex) {
            System.err.println("[NodeB] InvalidKeyException found when attempting to decrypt key K!");
        } finally {
            System.out.println("[NodeB] Key K decrypted successfully!...");
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
