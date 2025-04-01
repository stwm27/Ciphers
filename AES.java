import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;

class AES {
    private static final int[] S_BOX = {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    };

    private static final int[] INV_S_BOX = {
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
    };

    private static final int[] RCON = { 
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    };

    private byte[][] state; 
    private byte[][] roundkeys;
    
    private byte[][] expandKey(byte[] key) {
        //KEY = 16 BYTE
        byte[][] roundkeys = new byte[44][4];
    
        for (int i = 0; i < 4; i++) {
            System.arraycopy(key, i * 4, roundkeys[i], 0, 4);
        }
        for (int i = 4; i < 44; i++) {
            byte[] temp = roundkeys[i - 1].clone();
    
            if (i % 4 == 0) {
                temp = rotateWord(temp);
                temp = subWord(temp);

                int rconIndex = (i / 4) - 1; 
                if (rconIndex < RCON.length) {
                    temp[0] ^= RCON[rconIndex];
                } else {
                    throw new IllegalStateException("RCON index out of bounds");
                }
            }
            for (int j = 0; j < 4; j++) {
                roundkeys[i][j] = (byte) (roundkeys[i - 4][j] ^ temp[j]);
            }
        }
        return roundkeys;
    }

    private byte[] rotateWord(byte[] word) {
        byte temp = word[0];
        System.arraycopy(word, 1, word, 0, 3); // shifting bytes to the left
        word[3] = temp; // first byte to last position
        return word; 
    }

    private byte[] subWord(byte[] word) {
        for (int i = 0; i<4; i++) {
            word[i] = (byte) S_BOX[word[i] & 0xFF]; 
        }
        return word; 
    }

    //Encryption operation 
    private void subBytes() {
        for (int i=0; i<4; i++) {
            for (int j=0; j<4; j++) {
                state[i][j] = (byte) S_BOX[state[i][j] & 0xFF]; // for unsigned access
            }
        }
    }

    private void shiftRows() {
        for (int i = 1; i < 4; i++) {
            byte[] temp = new byte[4];
            for (int j = 0; j < 4; j++) {
                temp[j] = state[i][(j + i) % 4];
            }
            System.arraycopy(temp, 0, state[i], 0, 4);
        }
    }

    private byte mul(int a, byte b) {
        byte result = 0;
        byte highBit;
        for (int i = 0; i < 8; i++) {
            if ((b & 1) == 1) {
                result ^= a;
            }
            highBit = (byte) (a & 0x80);
            a <<= 1;
            if (highBit == 0x80) {
                a ^= 0x1B; // x^8 + x^4 + x^3 + x + 1 reduction
            }
            b >>= 1;
        }
        return result;
    } 

    private void mixColumns() {
        for (int j = 0; j < 4; j++) {
            byte[] column = new byte[4];
            for (int i = 0; i < 4; i++) {
                column[i] = state[i][j];
            }
            column = mixColumn(column);
            for (int i = 0; i < 4; i++) {
                state[i][j] = column[i];
            }
        }
    }
    
    private byte[] mixColumn(byte[] column) {
        byte[] result = new byte[4];
        result[0] = (byte) (mul(0x02, column[0]) ^ mul(0x03, column[1]) ^ column[2] ^ column[3]);
        result[1] = (byte) (column[0] ^ mul(0x02, column[1]) ^ mul(0x03, column[2]) ^ column[3]);
        result[2] = (byte) (column[0] ^ column[1] ^ mul(0x02, column[2]) ^ mul(0x03, column[3]));
        result[3] = (byte) (mul(0x03, column[0]) ^ column[1] ^ column[2] ^ mul(0x02, column[3]));
        return result;
    }
    
    private void addRoundKey(int round) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] ^= roundkeys[round * 4 + j][i];
            }
        }
    }

    public byte[] encrypt(byte[] plaintext, byte[] key) {
        state = new byte[4][4];
        for (int i = 0; i < 16; i++) {
            state[i % 4][i / 4] = plaintext[i];
        }

        roundkeys = expandKey(key);

        addRoundKey(0); // The initial round

        for (int round = 1; round < 10; round++) { // 9 main rounds
            subBytes();
            shiftRows();
            mixColumns();
            addRoundKey(round);
        }
        subBytes();
        shiftRows();
        addRoundKey(10); // Final Round (10th)

        byte[] ciphertext = new byte[16];
        for (int i = 0; i < 16; i++) {
            ciphertext[i] = state[i % 4][i / 4];
        }
        return ciphertext;
    }

    // Decryption operations
    private void invSubBytes() {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] = (byte) INV_S_BOX[state[i][j] & 0xFF];
            }
        }
    }
    
    private void invShiftRows() {
        for (int i = 1; i < 4; i++) {
            byte[] temp = new byte[4];
            for (int j = 0; j < 4; j++) {
                temp[j] = state[i][(j - i + 4) % 4];
            }
            System.arraycopy(temp, 0, state[i], 0, 4);
        }
    }

    private void invMixColumns() {
        for (int j = 0; j < 4; j++) {
            byte[] column = new byte[4];
            for (int i = 0; i < 4; i++) {
                column[i] = state[i][j];
            }
            column = invMixColumn(column);
            for (int i = 0; i < 4; i++) {
                state[i][j] = column[i];
            }
        }
    }

    private byte[] invMixColumn(byte[] column) {
        byte[] result = new byte[4];
        result[0] = (byte) (mul(0x0E, column[0]) ^ mul(0x0B, column[1]) ^ mul(0x0D, column[2]) ^ mul(0x09, column[3]));
        result[1] = (byte) (mul(0x09, column[0]) ^ mul(0x0E, column[1]) ^ mul(0x0B, column[2]) ^ mul(0x0D, column[3]));
        result[2] = (byte) (mul(0x0D, column[0]) ^ mul(0x09, column[1]) ^ mul(0x0E, column[2]) ^ mul(0x0B, column[3]));
        result[3] = (byte) (mul(0x0B, column[0]) ^ mul(0x0D, column[1]) ^ mul(0x09, column[2]) ^ mul(0x0E, column[3]));
        return result;
    }
 
    public byte[] decrypt(byte[] ciphertext, byte[] key) {
        state = new byte[4][4];
        for (int i = 0; i < 16; i++) {
            state[i % 4][i / 4] = ciphertext[i];
        }

        roundkeys = expandKey(key);

        addRoundKey(10); // Opening Round (10th)

        for (int round = 9; round > 0; round--) { // 9 main rounds
            invShiftRows();
            invSubBytes();
            addRoundKey(round);
            invMixColumns();
        }
        invShiftRows();
        invSubBytes();
        addRoundKey(0); // Final round (0th)

        byte[] plaintext = new byte[16];
        for (int i = 0; i < 16; i++) {
            plaintext[i] = state[i % 4][i / 4];
        }
        return plaintext;
    }

    public void encryptFile(String inputFile, String outputFile, byte[] key) throws IOException {
        byte[] fileData = Files.readAllBytes(Paths.get(inputFile));

        int padding = 16 - (fileData.length%16);
        if (padding == 0) {
            padding = 16;
        }

        byte[] paddedData = new byte[fileData.length + padding]; 
        System.arraycopy(fileData, 0, paddedData, 0, fileData.length);
        for (int i = fileData.length; i < paddedData.length; i++) {
            paddedData[i] = (byte) padding;
        }

        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            for (int i=0; i < paddedData.length; i+=16) {
                byte[] block = new byte[16];
                System.arraycopy(paddedData, i, block, 0, 16);
                byte[] encryptedBlock = encrypt(block, key);
                fos.write(encryptedBlock);
            }
        }
        System.out.println("The file is encrypted and saved as " + outputFile);
    }

    public void decryptFile(String inputFile, String outputFile, byte[] key) throws IOException {
        byte[] fileData = Files.readAllBytes(Paths.get(inputFile));
        
        if (fileData.length % 16 != 0) {
            throw new IllegalArgumentException("The encrypted file must be a multiple of 16");
        }
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (int i = 0; i < fileData.length; i += 16) {
            byte[] block = new byte[16];
            System.arraycopy(fileData, i, block, 0, 16);
            byte[] decryptedBlock = decrypt(block, key);
            baos.write(decryptedBlock);
        }
        
        byte[] decryptedData = baos.toByteArray();
        
        int padding = decryptedData[decryptedData.length - 1] & 0xFF; // Conversion to an unsigned value
        if (padding < 1 || padding > 16) {
            throw new IllegalArgumentException("Invalid padding in the decrypted file.");
        }
        int originalLength = decryptedData.length - padding;
        byte[] originalData = new byte[originalLength];
        System.arraycopy(decryptedData, 0, originalData, 0, originalLength);
        
        Files.write(Paths.get(outputFile), originalData);
        System.out.println("The file is decrypted and saved as " + outputFile);
    }    


    public static void main(String[] args) {
        AES aes = new AES();
        String inputFile = "7041e22c81095e3553900250de9582fd.jpeg";

        File file = new File(inputFile);
        if (!file.exists()) {
            System.err.println("File " + inputFile + " not found.");
            return;
        }

        String outputFile = "encrypted.bin";
        if (args.length >= 2) {
            inputFile = args[0];
            outputFile = args[1];
        }

        byte[] key = "0123456789ABCDEF".getBytes();
        try {
            aes.encryptFile(inputFile, outputFile, key);
        } catch (IOException e) {
            e.printStackTrace();
        }

        String encryptedFile = "encrypted.bin"; 
        String decryptedFile = "decrypt.jpeg";

        try {
            aes.decryptFile(encryptedFile, decryptedFile, key);
        } catch (IOException e) {
            e.printStackTrace();
        }
    } 
}