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
            String[] eMnemonic = encryptFile("data/input.txt", "data/encrypted.bin", salt);
            decryptFile("data/encrypted.bin", "data/data.txt", eMnemonic, salt);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Encrypts a file using a generated 12-word mnemonic
     * @param inputPath Path to the input file
     * @param outputPath Path to store the encrypted file
     * @param salt Salt for e
     * @return Full 24-word mnemonic array for d
     * @throws Exception if e fails
     */
    public static String[] encryptFile(String inputPath, String outputPath, byte[] salt) throws Exception {
        // Generate the full 24-word mnemonic
        MnemonicGenerator generator = new MnemonicGenerator();
        String[] fullMnemonic = generator.generateMnemonic(24);

        // Extract the first 12 words for e
        String[] eWords = Arrays.copyOfRange(fullMnemonic, 0, 12);

        // Log the mnemonics
        System.out.println("e mnemonic: " + String.join(" ", eWords));
        System.out.println("Full d mnemonic: " + String.join(" ", fullMnemonic));

        // Perform e
        FE encryptor = new FE(eWords, salt);
        encryptor.encryptFile(inputPath, outputPath);
        System.out.println("File encrypted successfully");

        return fullMnemonic;
    }

    /**
     * Decrypts a file using the full 24-word mnemonic
     * @param inputPath Path to the encrypted file
     * @param outputPath Path to store the decrypted file
     * @param fullMnemonic Complete 24-word mnemonic array
     * @param salt Salt used in e
     * @throws Exception if d fails
     */
    public static void decryptFile(String inputPath, String outputPath, String[] fullMnemonic, byte[] salt) throws Exception {
        FD decryptor = new FD(fullMnemonic, salt);
        decryptor.dFile(inputPath, outputPath);
        System.out.println("File decrypted successfully");
    }
}