import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.Key;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;


/**
 * Created by brianzhao on 2/2/16.
 */
public class JCEHw {
    private static final String PLAIN_FILE_NAME = "plaintext.txt";
    private static final String CIPH_FILE_NAME = "ciphertext.txt";
    private static final String DECRYPTED_FILE_NAME = "decrypted.txt";

    public static void main(String[] args) throws Exception{
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey key = keyGenerator.generateKey();

        File plaintext= new File(PLAIN_FILE_NAME);
        File ciphertext = encryptFile(plaintext, key);
        File decrypted = decryptFile(ciphertext, key);


    }

    public static File encryptFile(File plaintext, SecretKey key) throws Exception {
        File outputFile = new File(CIPH_FILE_NAME);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        FileInputStream fileInputStream = new FileInputStream(plaintext);
        byte[] plaintextBytes = new byte[(int) plaintext.length()];
        fileInputStream.read(plaintextBytes);

        byte[] ciphertextBytes = cipher.doFinal(plaintextBytes);

        FileOutputStream fileOutputStream = new FileOutputStream(outputFile);
        fileOutputStream.write(ciphertextBytes);

        fileInputStream.close();
        fileOutputStream.close();
        return outputFile;
    }

    public static File decryptFile(File ciphertext, SecretKey key) throws Exception {
        File decrypted = new File(DECRYPTED_FILE_NAME);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);

        FileInputStream fileInputStream = new FileInputStream(ciphertext);
        byte[] ciphertextBytes = new byte[(int) ciphertext.length()];
        fileInputStream.read(ciphertextBytes);

        byte[] plaintextBytes = cipher.doFinal(ciphertextBytes);

        FileOutputStream fileOutputStream = new FileOutputStream(decrypted);
        fileOutputStream.write(plaintextBytes);

        fileInputStream.close();
        fileOutputStream.close();
        return decrypted;
    }


    public static String byteArrayToString(byte[] input){
        StringBuilder result = new StringBuilder();
        for (byte x : input) {
            if (x == 0) {
                result.append(0);
            } else {
                result.append(1);
            }
        }
        return result.toString();
    }


}
