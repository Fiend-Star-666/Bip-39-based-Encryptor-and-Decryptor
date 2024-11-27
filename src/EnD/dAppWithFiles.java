package EnD;


import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class dAppWithFiles {
    public static void main(String[] args) {
        try {

            String encryptedFile = "data/enc.md";
            String outputFile = "data/dec.txt";

            // Read the salt
            String saltString = new String(Files.readAllBytes(Paths.get(encryptedFile + ".salt")));
            byte[] salt = Base64.getDecoder().decode(saltString);

            // Read the mnemonic
            String mnemonicString = new String(Files.readAllBytes(Paths.get(encryptedFile + ".mnemonic")));
            String[] fullMnemonic = mnemonicString.split(" ");

            if (fullMnemonic.length != 24) {
                throw new IllegalArgumentException("Invalid mnemonic: expected 24 words");
            }

            // Perform decryption
            FileDecryptor decryptor = new FileDecryptor(fullMnemonic, salt);
            decryptor.decryptFile(encryptedFile, outputFile);

            System.out.println("File decrypted successfully");
        } catch (Exception e) {
            System.err.println("Decryption error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
