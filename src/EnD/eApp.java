package EnD;

import java.security.SecureRandom;
import java.util.Arrays;
import java.nio.file.Paths;
import java.util.Base64;
import java.io.Console;

public class eApp {
    public static void main(String[] args) {
        try {
            String inputFile = "data/input.txt";
            String outputFile = "data/enc.md";
            Console console = System.console();

            if (console == null) {
                System.err.println("Console not available - running in non-interactive mode");
                return;
            }

            // Generate salt
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);

            // Generate mnemonics
            MnemonicGenerator generator = new MnemonicGenerator();
            String[] fullMnemonic = generator.generateMnemonic(24);
            String[] encryptionWords = Arrays.copyOfRange(fullMnemonic, 0, 12);

            // Encrypt the file
            FileEncryptor encryptor = new FileEncryptor(encryptionWords, salt);
            encryptor.encryptFile(inputFile, outputFile);

            // Display sensitive information to user securely
            console.writer().println("\nIMPORTANT: Please securely record the following information.\n");
            console.writer().println("Mnemonic phrase (required for decryption):");
            console.writer().println(String.join(" ", fullMnemonic));
            console.writer().println("\nSalt (Base64, required for decryption):");
            console.writer().println(Base64.getEncoder().encodeToString(salt));

            // Immediate secure cleanup
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(fullMnemonic, null);
            Arrays.fill(encryptionWords, null);
            System.gc();

            console.writer().println("\nFile encrypted successfully.");
            console.writer().println("WARNING: Store the mnemonic phrase and salt securely!");
            console.writer().println("Both pieces of information will be required for decryption.");

            // Prompt user to confirm they've recorded the information
            console.readLine("\nPress Enter to confirm you have securely recorded this information...");

            // Clear the console if possible
            if (System.getProperty("os.name").contains("Windows")) {
                new ProcessBuilder("cmd", "/c", "cls").inheritIO().start().waitFor();
            } else {
                new ProcessBuilder("clear").inheritIO().start().waitFor();
            }

        } catch (Exception e) {
            System.err.println("Encryption error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}