package EnD;

import java.security.SecureRandom;
import java.util.Arrays;


public class Main {
    public static void main(String[] args) {
        try {
            // Generate random salt
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);

            // Generate the full 24-word mnemonic first
            MnemonicGenerator generator = new MnemonicGenerator();
            String[] fullMnemonic = generator.generateMnemonic(24);

            // Extract the first 12 words for encryption
            String[] encryptionWords = Arrays.copyOfRange(fullMnemonic, 0, 12);

            System.out.println("Encryption mnemonic: " + String.join(" ", encryptionWords));
            System.out.println("Full decryption mnemonic: " + String.join(" ", fullMnemonic));

            // Encrypt file using first 12 words
            FileEncryptor encryptor = new FileEncryptor(encryptionWords, salt);
            encryptor.encryptFile("data/input.txt", "data/encrypted.bin");
            System.out.println("File encrypted successfully");

            // Decrypt file using all 24 words
            FileDecryptor decryptor = new FileDecryptor(fullMnemonic, salt);
            decryptor.decryptFile("data/encrypted.bin", "data/data.txt");
            System.out.println("File decrypted successfully");

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
