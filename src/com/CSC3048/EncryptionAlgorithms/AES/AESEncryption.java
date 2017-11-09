package com.CSC3048.EncryptionAlgorithms.AES;

import com.CSC3048.EncryptionAlgorithms.ISymmetricEncryptionAlgorithm;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

//AES - 128 bit
public class AESEncryption implements ISymmetricEncryptionAlgorithm {
    BinaryHelper binaryHelper = new BinaryHelper();
    //Size of key
    int Nk = 4;
    //Number of rounds
    int Nr = 10;
    //Number of words
    int Nb = Nr + 1;
    String[][] startingKey = new String[][]{
            {"2b", "28", "ab", "09"},
            {"7e", "ae", "f7", "cf"},
            {"15", "d2", "15", "4f"},
            {"16", "a6", "88", "3c"}
    };
    private String[][] standardSBox = new String[][]{
            {"63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76"},
            {"ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0"},
            {"b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15"},
            {"04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75"},
            {"09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84"},
            {"53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf"},
            {"d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8"},
            {"51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2"},
            {"cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73"},
            {"60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db"},
            {"e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79"},
            {"e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08"},
            {"ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a"},
            {"70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e"},
            {"e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df"},
            {"8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16"}
    };
    private String[][] invSBox = new String[][]{
            {"52", "09", "6a", "d5", "30", "36", "a5", "38", "bf", "40", "a3", "9e", "81", "f3", "d7", "fb"},
            {"7c", "e3", "39", "82", "9b", "2f", "ff", "87", "34", "8e", "43", "44", "c4", "de", "e9", "cb"},
            {"54", "7b", "94", "32", "a6", "c2", "23", "3d", "ee", "4c", "95", "0b", "42", "fa", "c3", "4e"},
            {"08", "2e", "a1", "66", "28", "d9", "24", "b2", "76", "5b", "a2", "49", "6d", "8b", "d1", "25"},
            {"72", "f8", "f6", "64", "86", "68", "98", "16", "d4", "a4", "5c", "cc", "5d", "65", "b6", "92"},
            {"6c", "70", "48", "50", "fd", "ed", "b9", "da", "5e", "15", "46", "57", "a7", "8d", "9d", "84"},
            {"90", "d8", "ab", "00", "8c", "bc", "d3", "0a", "f7", "e4", "58", "05", "b8", "b3", "45", "06"},
            {"d0", "2c", "1e", "8f", "ca", "3f", "0f", "02", "c1", "af", "bd", "03", "01", "13", "8a", "6b"},
            {"3a", "91", "11", "41", "4f", "67", "dc", "ea", "97", "f2", "cf", "ce", "f0", "b4", "e6", "73"},
            {"96", "ac", "74", "22", "e7", "ad", "35", "85", "e2", "f9", "37", "e8", "1c", "75", "df", "6e"},
            {"47", "f1", "1a", "71", "1d", "29", "c5", "89", "6f", "b7", "62", "0e", "aa", "18", "be", "1b"},
            {"fc", "56", "3e", "4b", "c6", "d2", "79", "20", "9a", "db", "c0", "fe", "78", "cd", "5a", "f4"},
            {"1f", "dd", "a8", "33", "88", "07", "c7", "31", "b1", "12", "10", "59", "27", "80", "ec", "5f"},
            {"60", "51", "7f", "a9", "19", "b5", "4a", "0d", "2d", "e5", "7a", "9f", "93", "c9", "9c", "ef"},
            {"a0", "e0", "3b", "4d", "ae", "2a", "f5", "b0", "c8", "eb", "bb", "3c", "83", "53", "99", "61"},
            {"17", "2b", "04", "7e", "ba", "77", "d6", "26", "e1", "69", "14", "63", "55", "21", "0c", "7d"}
    };
    private int[][] mixColumnMatrix = new int[][]{
            {2, 3, 1, 1},
            {1, 2, 3, 1},
            {1, 1, 2, 3},
            {3, 1, 1, 2}
    };
    private String[][] invMixColumnMatrix = new String[][]{
            {"0e", "0b", "0d", "09"},
            {"09", "0e", "0b", "0d"},
            {"0d", "09", "0e", "0b"},
            {"0b", "0d", "09", "0e"}
    };
    private String symmetricKey;

    /**
     * This constructor allows for a previously generated key to be used
     *
     * @param key
     */
    public AESEncryption(String[][] key) {
        symmetricKey = symmetricKeyToString(key);
        startingKey = key;
    }

    /**
     * The default constructor that will generate and use a random key
     */
    public AESEncryption() {
        startingKey = generateKey();
        symmetricKey = symmetricKeyToString(startingKey);
    }

    /**
     * Generates a random key. It is static so that it can be used in the constructor above
     *
     * @return
     */
    public static String[][] generateKey() {
        String[][] key = new String[4][4];

        Random rng = new Random();

        for (int row = 0; row < key.length; row++) {
            for (int col = 0; col < key[row].length; col++) {
                int randomNumber = rng.nextInt(255);
                String hexString = Integer.toHexString(randomNumber);
                if (hexString.length() != 2) {
                    hexString = 0 + hexString;
                }
                key[row][col] = hexString;
            }
        }

        return key;
    }

    /**
     * Returns the string representation of the symmetric key
     *
     * @param symmetricKey
     * @return
     */
    private static String symmetricKeyToString(String[][] symmetricKey) {
        String outputString = "";
        for (int row = 0; row < symmetricKey.length; row++) {
            for (int col = 0; col < symmetricKey[row].length; col++) {
                if (col == 1 || col == 2 || col == 3) {
                    outputString += ",";
                }
                outputString += symmetricKey[row][col];
                if (col == 3 && row != 3) {
                    outputString += ";";
                }
            }
        }
        return outputString;
    }

    /**
     * Takes the plain text string that the user wants to encrypt and returns cipher text
     *
     * @param plainText
     * @return - Cipher text string
     */
    @Override
    public String encrypt(String plainText) {

        while (plainText.length() % 16 != 0) {
            plainText += " ";
        }

        //8 bits in one ascii char
        //16 chars in an input
        String cipherText = "";
        String asciiText = convertPlaintextToHex(plainText);
        List<String[][]> blockArray = convertToBlocks(asciiText);

        AESKeyGeneration keyGeneration = new AESKeyGeneration();

        String[][] expandedKey = keyGeneration.expandKey(startingKey);

        for (String[][] block : blockArray) {
            String[][] key = new String[4][4];
            for (int keyCounterRow = 0; keyCounterRow < 4; keyCounterRow++) {
                for (int keyCounterCol = 0; keyCounterCol < 4; keyCounterCol++) {
                    key[keyCounterRow][keyCounterCol] = expandedKey[keyCounterCol][keyCounterRow];
                }
            }

            addRoundKey(block, key); //0

            int Nr = 10;
            //Nr-1 times (start at 1)
            for (int i = 1; i < Nr; i++) {
                subBytes(block, standardSBox);
                shiftRows(block);
                block = mixColumn(block);

                for (int keyCounterRow = 0; keyCounterRow < 4; keyCounterRow++) {
                    for (int keyCounterCol = 0; keyCounterCol < 4; keyCounterCol++) {
                        key[keyCounterRow][keyCounterCol] = expandedKey[i * 4 + keyCounterCol][keyCounterRow];
                    }
                }

                addRoundKey(block, key); //1 to Nr-1
            }

            //Final round
            subBytes(block, standardSBox);
            shiftRows(block);

            for (int keyCounterRow = 0; keyCounterRow < 4; keyCounterRow++) {
                for (int keyCounterCol = 0; keyCounterCol < 4; keyCounterCol++) {
                    key[keyCounterRow][keyCounterCol] = expandedKey[40 + keyCounterCol][keyCounterRow];
                }
            }

            addRoundKey(block, key); //Nr
            cipherText += convertBlockToText(block);
        }

        return cipherText;
    }

    /**
     * Converts the block to a single string
     *
     * @param block
     * @return
     */
    private String convertBlockToText(String[][] block) {
        String result = "";

        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                String rawHex = block[row][col];

                if (rawHex.length() == 1) {
                    rawHex = 0 + rawHex;
                }

                if (rawHex == null) {
                    continue;
                }

                result += rawHex;
            }
            result += " ";
        }

        return result;
    }

    /**
     * Converts plainText string into a hexadecimal string
     *
     * @param plainText
     * @return
     */
    private String convertPlaintextToHex(String plainText) {
        String result = "";

        for (char c : plainText.toCharArray()) {
            int charIntValue = (int) c;

            String hexValue = Integer.toHexString(charIntValue);

            if (hexValue.length() != 2) {
                hexValue = 0 + hexValue;
            }

            result += hexValue;
        }

        return result;
    }

    /**
     * This takes plain text and breaks it into 128 bit blocks and converts the characters to Hex
     *
     * @param text
     * @return - A collection of the blocks (2-D arrays of 128bit)
     */
    private List<String[][]> convertToBlocks(String text) {
        List<String[][]> blocks = new ArrayList<>();
        char[] charArray = text.toCharArray();

        String[][] block = new String[4][4];

        int col = 0;
        int row = 0;
        for (int i = 0; i + 1 <= charArray.length; i = i + 2) {
            //Take chars in sets of 2. This means hex being passed in needs to be 04 instead of just 4
            String firstHexByte = String.valueOf(charArray[i]) + String.valueOf(charArray[i + 1]);

            block[row][col] = firstHexByte;

            col++;

            if (col != 0 && col % 4 == 0) {
                col = 0;
                row++;
            }

            if (row > 0 && row % 4 == 0) {
                blocks.add(block);
                col = 0;
                row = 0;
                block = new String[4][4];
            }
        }

        return blocks;
    }

    /**
     * This converts the plaintext char list to a 2-D array by converting the plain characters to Hex values
     *
     * @param plainTextCharBlock - Less than 16 char's
     * @return - 2-D array of chars
     */
    private String[][] createStateArray(List<Character> plainTextCharBlock) {
        String[][] stateArray = new String[4][4];
        int columnCount = 0;
        for (int j = 0; j < plainTextCharBlock.size(); j++) {
            char c = plainTextCharBlock.get(j);

            if (j > 0 && j % 4 == 0) {
                columnCount++;
            }

            stateArray[columnCount][j % 4] = String.valueOf(c);
        }

        return stateArray;
    }

    /**
     * Adds the round key by performing an XOR operation on the key column and the block column
     *
     * @param block
     * @param roundKey
     */
    private void addRoundKey(String[][] block, String[][] roundKey) {
        //XOR each byte with the key for that round; The key is modified for each round of the operation
        //Round key column[i] XOR key column[i]

        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                String roundBinString = Integer.toBinaryString(Integer.parseInt(roundKey[row][col], 16));
                String rawHexValue = block[row][col];
                if (rawHexValue == null) {
                    continue;
                }
                String blockBinString = Integer.toBinaryString(Integer.parseInt(rawHexValue, 16));

                while (roundBinString.length() != 8) {
                    roundBinString = 0 + roundBinString;
                }

                while (blockBinString.length() != 8) {
                    blockBinString = 0 + blockBinString;
                }

                String resultBinString = binaryHelper.xor(roundBinString, blockBinString);

                while (resultBinString.length() != 8) {
                    resultBinString = 0 + blockBinString;
                }

                String resultHexString = Integer.toHexString(Integer.parseInt(resultBinString, 2));

                if (resultHexString.length() != 2) {
                    resultHexString = 0 + resultHexString;
                }

                block[row][col] = resultHexString;
            }
        }
    }

    /**
     * Used the Hex S-Box to substitute the values in the block
     *
     * @param block - alters this block instead of returning a different instance
     */
    private void subBytes(String[][] block, String[][] sbox) {
        //use of an S-box to do a byte by byte substitution of the entire block
        //Replace firstBlock with all the matching locations of standardSBox
        //53 becomes row 5 column 3
        for (int row = 0; row < 4; row++) {
            subWord(block[row], sbox);
        }
    }

    /**
     * Replaces hex in the block to hex from the sbox (uses different sbox for encryption and decryption) by using the
     * first hex char as the row and the second hex char as the column
     *
     * @param block
     * @param sbox
     */
    private void subWord(String[] block, String[][] sbox) {
        for (int col = 0; col < 4; col++) {
            String byteToReplace = block[col];
            if (byteToReplace == null) {
                continue;
            }

            if (byteToReplace.length() == 1) {
                byteToReplace = 0 + byteToReplace;
            }

            String sboxRowHex = byteToReplace.substring(0, 1);
            String sboxColHex = byteToReplace.substring(1, 2);
            int sboxRowDec = Integer.parseInt(sboxRowHex, 16);
            int sboxColDec = Integer.parseInt(sboxColHex, 16);
            block[col] = sbox[sboxRowDec][sboxColDec];
        }
    }

    /**
     * Shifts the items in the column. Index  1 rotates by 1 and index 2 rotates by 2 etc
     *
     * @param block - alters this block instead of returning a different instance
     */
    private void shiftRows(String[][] block) {
        //Transposition or permutation through offsetting each row in the table
        //1st row not shifted, 2nd row shift 1, 3rd row shift 2 and 4th row shift 3
        for (int row = 1; row < 4; row++) {
            String[] newRow = new String[4];
            for (int col = 0; col < 4; col++) {
                int positionToSwap = (col + row) % 4;
                newRow[col] = block[row][positionToSwap];
            }
            block[row] = newRow;
        }
    }

    /**
     * Performs a matrix vector multiplication
     *
     * @param block
     * @return - the result of the evaluation
     */
    private String[][] mixColumn(String[][] block) {
        //A substitution of each value in a column based on a function of the values of the data in the column
        //Matrix vector multiplication
        String[][] newMatrix = new String[4][4];

        for (int row = 0; row < 4; row++) {
            int[] rowOfMatrix = mixColumnMatrix[row];
            String[] multiplicationResults = new String[4];

            String result = "00000000";

            for (int masterCol = 0; masterCol < 4; masterCol++) {
                result = "00000000";
                for (int col = 0; col < 4; col++) {
                    //XOR each of these multiplications together
                    String binaryMultiplicationResult = binaryHelper.binaryMultiplication(rowOfMatrix[col], block[col][masterCol]);

                    if (binaryMultiplicationResult == null) {
                        continue;
                    }

                    while (binaryMultiplicationResult.length() != 8) {
                        binaryMultiplicationResult = 0 + binaryMultiplicationResult;
                    }

                    multiplicationResults[col] = binaryMultiplicationResult;
                }

                for (String multiplicationResult : multiplicationResults) {
                    if (multiplicationResult == null) {
                        continue;
                    }

                    result = binaryHelper.xor(multiplicationResult, result);
                }

                if (result == null) {
                    continue;
                }

                int intResult = Integer.parseInt(result, 2);
                result = Integer.toHexString(intResult);
                newMatrix[row][masterCol] = result;
            }
        }

        return newMatrix;
    }

    /**
     * Takes the cipherText and decrypts it to plaintext again
     *
     * @param cipherText
     * @return - Plaintext
     */
    @Override
    public String decrypt(String cipherText) {
        //Trim all white spaces that were used to make it easy to read (Clean up input)
        cipherText = cipherText.replace(" ", "");

        List<String[][]> cipherBlocks = convertToBlocks(cipherText);

        AESKeyGeneration keyGeneration = new AESKeyGeneration();

        String[][] expandedKey = keyGeneration.expandKey(startingKey);

        String result = "";

        for (String[][] cipherBlock : cipherBlocks) {
            String[][] key = new String[4][4];

            for (int keyCounterRow = 0; keyCounterRow < 4; keyCounterRow++) {
                for (int keyCounterCol = 0; keyCounterCol < 4; keyCounterCol++) {
                    key[keyCounterRow][keyCounterCol] = expandedKey[40 + keyCounterCol][keyCounterRow];
                }
            }

            addRoundKey(cipherBlock, key);

            for (int round = Nr - 1; round >= 1; round--) {
                invShiftRows(cipherBlock);
                subBytes(cipherBlock, invSBox);
                for (int keyCounterRow = 0; keyCounterRow < 4; keyCounterRow++) {
                    for (int keyCounterCol = 0; keyCounterCol < 4; keyCounterCol++) {
                        key[keyCounterRow][keyCounterCol] = expandedKey[round * 4 + keyCounterCol][keyCounterRow];
                    }
                }

                addRoundKey(cipherBlock, key);
                cipherBlock = invMixColumn(cipherBlock);
            }

            invShiftRows(cipherBlock);
            subBytes(cipherBlock, invSBox);
            for (int keyCounterRow = 0; keyCounterRow < 4; keyCounterRow++) {
                for (int keyCounterCol = 0; keyCounterCol < 4; keyCounterCol++) {
                    key[keyCounterRow][keyCounterCol] = expandedKey[keyCounterCol][keyCounterRow];
                }
            }

            addRoundKey(cipherBlock, key);
            result += convertBlockToPlainText(cipherBlock);
        }

        return result;
    }

    /**
     * The inverse of the mix column operation.
     *
     * @param cipherBlock
     * @return
     */
    private String[][] invMixColumn(String[][] cipherBlock) {
        //A substitution of each value in a column based on a function of the values of the data in the column
        //Matrix vector multiplication
        String[][] newMatrix = new String[4][4];

        for (int row = 0; row < 4; row++) {
            String[] rowOfMatrix = invMixColumnMatrix[row];
            String[] multiplicationResults = new String[4];

            String result = "00000000";

            for (int masterCol = 0; masterCol < 4; masterCol++) {
                result = "00000000";

                for (int col = 0; col < 4; col++) {
                    String hexMatrixValue = rowOfMatrix[col];
                    String hexCipherValue = cipherBlock[col][masterCol];
                    String hexBinaryMultiplicationResult = binaryHelper.HexBinaryMultiplication(hexMatrixValue, hexCipherValue);
                    int decBinaryMultiplicationResult = Integer.parseInt(hexBinaryMultiplicationResult, 16);
                    multiplicationResults[col] = Integer.toBinaryString(decBinaryMultiplicationResult);
                }

                for (String multiplicationResult : multiplicationResults) {
                    if (multiplicationResult == null) {
                        continue;
                    }

                    while (multiplicationResult.length() != 8) {
                        multiplicationResult = 0 + multiplicationResult;
                    }

                    result = binaryHelper.xor(multiplicationResult, result);
                }

                if (result == null) {
                    continue;
                }

                int intResult = Integer.parseInt(result, 2);
                result = Integer.toHexString(intResult);

                if (result.length() != 2) {
                    result = 0 + result;
                }

                newMatrix[row][masterCol] = result;
            }
        }

        return newMatrix;
    }

    /**
     * The inverse of the shift row operation
     *
     * @param cipherBlock
     */
    private void invShiftRows(String[][] cipherBlock) {
        //First row not shifted
        for (int row = 1; row < 4; row++) {
            String[] newRow = new String[4];
            for (int col = 0; col < 4; col++) {
                int positionToSwap = ((col - row) + 4) % 4;//(col+row)%4;
                newRow[col] = cipherBlock[row][positionToSwap];
            }
            cipherBlock[row] = newRow;
        }
    }

    /**
     * Converts a hex block back to a plaintext string
     *
     * @param cipherBlock
     * @return
     */
    private String convertBlockToPlainText(String[][] cipherBlock) {
        String result = "";
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                String hex = cipherBlock[col][row];
                int dec = Integer.parseInt(hex, 16);
                char c = (char) dec;
                result += String.valueOf(c);
            }
        }
        return result;
    }

    public String getSymmetricKey() {
        return symmetricKey;
    }
}
