package EnD;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;

public class FileEncryptor {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    private static final int KEY_LENGTH = 256;
    private static final int HASH_LENGTH = 64;
    private static final int BUFFER_SIZE = 8192; // 8KB chunks

    private final String[] mnemonicWords;
    private final byte[] salt;

    public FileEncryptor(String[] mnemonicWords, byte[] salt) {
        if (mnemonicWords == null || salt == null) {
            throw new IllegalArgumentException("Mnemonic words and salt cannot be null");
        }
        if (mnemonicWords.length != 12) {
            throw new IllegalArgumentException("Encryption requires first 12 words");
        }

        this.mnemonicWords = Arrays.copyOf(mnemonicWords, mnemonicWords.length);
        this.salt = Arrays.copyOf(salt, salt.length);
    }

    public void encryptFile(String inputFile, String outputFile) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        SecretKey encryptionKey = generateKeyFromMnemonic(mnemonicWords, salt);
        byte[] mnemonicHash = generateMnemonicHash(mnemonicWords);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, spec);
        cipher.updateAAD(mnemonicHash);

        // Write header information first
        try (OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFile))) {
            out.write(iv);
            out.write(mnemonicHash);

            // Process file in chunks
            try (InputStream in = new BufferedInputStream(new FileInputStream(inputFile))) {
                byte[] buffer = new byte[BUFFER_SIZE];
                int bytesRead;
                byte[] encryptedChunk;

                while ((bytesRead = in.read(buffer)) != -1) {
                    if (bytesRead == BUFFER_SIZE) {
                        // Full chunk
                        encryptedChunk = cipher.update(buffer);
                    } else {
                        // Last chunk
                        encryptedChunk = cipher.update(Arrays.copyOf(buffer, bytesRead));
                    }

                    if (encryptedChunk != null) {
                        out.write(encryptedChunk);
                    }
                }

                // Write the final block
                encryptedChunk = cipher.doFinal();
                if (encryptedChunk != null) {
                    out.write(encryptedChunk);
                }
            }
        }
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
