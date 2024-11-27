package EnD;

import java.security.SecureRandom;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) {
        try {
            // Generate random salt for both operations
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);

            // Example usage of both methods
            String[] encryptionMnemonic = encryptFile("data/input.txt", "data/encrypted.bin", salt);
            decryptFile("data/encrypted.bin", "data/data.txt", encryptionMnemonic, salt);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Encrypts a file using a generated 12-word mnemonic
     * @param inputPath Path to the input file
     * @param outputPath Path to store the encrypted file
     * @param salt Salt for encryption
     * @return Full 24-word mnemonic array for decryption
     * @throws Exception if encryption fails
     */
    public static String[] encryptFile(String inputPath, String outputPath, byte[] salt) throws Exception {
        // Generate the full 24-word mnemonic
        MnemonicGenerator generator = new MnemonicGenerator();
        String[] fullMnemonic = generator.generateMnemonic(24);

        // Extract the first 12 words for encryption
        String[] encryptionWords = Arrays.copyOfRange(fullMnemonic, 0, 12);

        // Log the mnemonics
        System.out.println("Encryption mnemonic: " + String.join(" ", encryptionWords));
        System.out.println("Full decryption mnemonic: " + String.join(" ", fullMnemonic));

        // Perform encryption
        FileEncryptor encryptor = new FileEncryptor(encryptionWords, salt);
        encryptor.encryptFile(inputPath, outputPath);
        System.out.println("File encrypted successfully");

        return fullMnemonic;
    }

    /**
     * Decrypts a file using the full 24-word mnemonic
     * @param inputPath Path to the encrypted file
     * @param outputPath Path to store the decrypted file
     * @param fullMnemonic Complete 24-word mnemonic array
     * @param salt Salt used in encryption
     * @throws Exception if decryption fails
     */
    public static void decryptFile(String inputPath, String outputPath, String[] fullMnemonic, byte[] salt) throws Exception {
        FileDecryptor decryptor = new FileDecryptor(fullMnemonic, salt);
        decryptor.decryptFile(inputPath, outputPath);
        System.out.println("File decrypted successfully");
    }
}