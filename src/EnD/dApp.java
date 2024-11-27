package EnD;

import java.util.Base64;
import java.io.Console;
import java.util.Arrays;

public class dApp {
    public static void main(String[] args) {
        try {
            String encryptedFile = "data/enc.md";
            String outputFile = "data/dec.txt";
            Console console = System.console();

            if (console == null) {
                System.err.println("Console not available - running in non-interactive mode");
                return;
            }

            // Collect mnemonic phrase securely
            console.writer().println("Please enter your 24-word mnemonic phrase (space-separated):");
            String mnemonicInput = console.readLine();
            String[] fullMnemonic = mnemonicInput.trim().split("\\s+");

            if (fullMnemonic.length != 24) {
                throw new IllegalArgumentException("Invalid mnemonic: expected 24 words, got " + fullMnemonic.length);
            }

            // Collect salt securely
            console.writer().println("\nPlease enter your Base64-encoded salt:");
            String saltString = console.readLine().trim();
            byte[] salt;

            try {
                salt = Base64.getDecoder().decode(saltString);
                if (salt.length != 16) {
                    throw new IllegalArgumentException("Invalid salt length: expected 16 bytes");
                }
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Invalid salt format: must be valid Base64");
            }

            // Perform decryption
            FileDecryptor decryptor = new FileDecryptor(fullMnemonic, salt);
            decryptor.decryptFile(encryptedFile, outputFile);

            // Clean up sensitive data
            Arrays.fill(fullMnemonic, null);
            Arrays.fill(salt, (byte) 0);
            System.gc();

            console.writer().println("\nFile decrypted successfully to: " + outputFile);

            // Clear the console
            if (System.getProperty("os.name").contains("Windows")) {
                new ProcessBuilder("cmd", "/c", "cls").inheritIO().start().waitFor();
            } else {
                new ProcessBuilder("clear").inheritIO().start().waitFor();
            }

        } catch (Exception e) {
            System.err.println("Decryption error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
