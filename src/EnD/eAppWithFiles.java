package EnD;

import java.security.SecureRandom;
import java.util.Arrays;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class eAppWithFiles {
    public static void main(String[] args) {
        try {

            String inputFile = "data/input.txt";
            String outputFile = "data/enc.md";

            // Generate and save salt
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            String saltString = Base64.getEncoder().encodeToString(salt);
            Files.write(Paths.get(outputFile + ".salt"), saltString.getBytes());

            // Generate mnemonics and perform encryption
            MnemonicGenerator generator = new MnemonicGenerator();
            String[] fullMnemonic = generator.generateMnemonic(24);
            String[] encryptionWords = Arrays.copyOfRange(fullMnemonic, 0, 12);

            // Encrypt the file
            FileEncryptor encryptor = new FileEncryptor(encryptionWords, salt);
            encryptor.encryptFile(inputFile, outputFile);

            // Save the full mnemonic for secure transfer
            Files.write(Paths.get(outputFile + ".mnemonic"),
                    String.join(" ", fullMnemonic).getBytes());

            System.out.println("File encrypted successfully");
            System.out.println("WARNING: Keep the generated .mnemonic file secure!");
            System.out.println("Both the .salt file and .mnemonic file are required for decryption.");
        } catch (Exception e) {
            System.err.println("Encryption error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
