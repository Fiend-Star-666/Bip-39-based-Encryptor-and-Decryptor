package EnD;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;


public class FD {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    private static final int HASH_LENGTH = 64;
    private static final int KEY_LENGTH = 256;

    private final String[] mnemonicWords;
    private final byte[] salt;

    public FD(String[] mnemonicWords, byte[] salt) {
        if (mnemonicWords == null || salt == null) {
            throw new IllegalArgumentException("Mnemonic words and salt cannot be null");
        }
        if (mnemonicWords.length != 24) {
            throw new IllegalArgumentException("D requires full 24-word mnemonic");
        }

        this.mnemonicWords = Arrays.copyOf(mnemonicWords, mnemonicWords.length);
        this.salt = Arrays.copyOf(salt, salt.length);
    }

    public void dFile(String inputFile, String outputFile) throws Exception {
        // Use first 12 words for d
        String[] dWords = Arrays.copyOfRange(mnemonicWords, 0, 12);

        // Read and parse the encrypted file
        byte[] fileContent = Files.readAllBytes(Paths.get(inputFile));
        if (fileContent.length < GCM_IV_LENGTH + HASH_LENGTH + GCM_TAG_LENGTH) {
            throw new SecurityException("Encrypted file is too short");
        }

        byte[] iv = Arrays.copyOfRange(fileContent, 0, GCM_IV_LENGTH);
        byte[] storedHash = Arrays.copyOfRange(fileContent, GCM_IV_LENGTH, GCM_IV_LENGTH + HASH_LENGTH);
        byte[] encryptedData = Arrays.copyOfRange(fileContent, GCM_IV_LENGTH + HASH_LENGTH, fileContent.length);

        // Verify the d words
        byte[] dHash = generateMnemonicHash(dWords);
        if (!MessageDigest.isEqual(storedHash, dHash)) {
            throw new SecurityException("Invalid d mnemonic words");
        }

        // Generate d key and decrypt
        SecretKey dKey = generateKeyFromMnemonic(dWords, salt);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, dKey, spec);
        cipher.updateAAD(storedHash);

        byte[] decryptedData = cipher.doFinal(encryptedData);
        Files.write(Paths.get(outputFile), decryptedData);
    }

    private SecretKey generateKeyFromMnemonic(String[] words, byte[] salt) throws Exception {
        String mnemonic = String.join(" ", words);
        char[] mnemonicChars = mnemonic.toCharArray();
        try {
            PBEKeySpec keySpec = new PBEKeySpec(mnemonicChars, salt, 2048, KEY_LENGTH);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            byte[] keyBytes = factory.generateSecret(keySpec).getEncoded();
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            Arrays.fill(mnemonicChars, '\0');
        }
    }

    private byte[] generateMnemonicHash(String[] words) throws Exception {
        String mnemonic = String.join(" ", words);
        byte[] mnemonicBytes = mnemonic.getBytes(StandardCharsets.UTF_8);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            return digest.digest(mnemonicBytes);
        } finally {
            Arrays.fill(mnemonicBytes, (byte) 0);
        }
    }
}