package com.CSC3048.EncryptionAlgorithms.AES;

public class AESKeyGeneration {
    //Size of key
    int Nk = 4;
    //Number of rounds
    int Nr = 10;
    //Number of words
    int Nb = Nr + 1;

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
    private String[][] RCon = new String[][]{
            {"01", "00", "00", "00"},
            {"02", "00", "00", "00"},
            {"04", "00", "00", "00"},
            {"08", "00", "00", "00"},
            {"10", "00", "00", "00"},
            {"20", "00", "00", "00"},
            {"40", "00", "00", "00"},
            {"80", "00", "00", "00"},
            {"1b", "00", "00", "00"},
            {"36", "00", "00", "00"}
    };

    /**
     * The entry point for Key Generation
     * @param key
     * @return
     */
    public String[][] expandKey(String[][] key) {
        String[][] w = new String[44][4];

        //Iteration
        int i = 0;

        while (i < Nk) {
            //1 2 3 4 becomes 2 3 4 1
            String[] curKey = {key[0][i], key[1][i], key[2][i], key[3][i]};
            w[i] = curKey;
            i++;
        }

        i = Nk;

        while (i < 44) {
            String[] temp = w[i - 1];

            if (i % Nk == 0) {
                String[] rotWordResult = rotWord(temp);
                String[] subWordResult = subWord(rotWordResult);
                String[] rconResult = rcon(i / Nk);
                temp = xor(subWordResult, rconResult);
            } else if (Nk > 6 && i % Nk == 4) {
                temp = subWord(temp);
            }

            String[] xorResult = xor(temp, w[i - Nk]);

            w[i] = xorResult;
            i++;
        }

        return w;
    }

    /**
     * Rotate the block
     * @param block
     * @return
     */
    public String[] rotWord(String[] block) {
        String[] rotWord = {block[1], block[2], block[3], block[0]};
        return rotWord;
    }

    /**
     * Substitute the values using the standard AES sbox
     * @param block
     * @return
     */
    private String[] subWord(String[] block) {
        String[] subWord = new String[4];

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
            subWord[col] = standardSBox[sboxRowDec][sboxColDec];
        }

        return subWord;
    }

    /**
     * Performs an exclusive or operation on two binary strings
     *
     * @param one
     * @param two
     * @return - the result of the XOR operation
     */
    private String[] xor(String[] one, String[] two) {
        if (one == null || two == null) {
            return null;
        }

        String[] xorResult = new String[4];

        for (int counter = 0; counter < 4; counter++) {
            String valueOne = one[counter];
            String valueTwo = two[counter];

            if (valueOne.length() != 2) {
                valueOne = 0 + valueOne;
            }

            if (valueTwo.length() != 2) {
                valueTwo = 0 + valueTwo;
            }

            int result = Integer.parseInt(valueOne, 16) ^ Integer.parseInt(valueTwo, 16);

            String hexResult = Integer.toHexString(result);

            if (hexResult.length() != 2) {
                hexResult = 0 + hexResult;
            }

            xorResult[counter] = hexResult;
        }


        return xorResult;
    }

    /**
     * Had some trouble getting this method to work, see comments below
     *
     * @param i
     * @return
     */
    private String[] rcon(int i) {
//The commented out code below works for iterations 1 - 35 as discribed in the comment we could not make it work for
// the last 2 values so as Rcon is a constant we decided to hard code it

        //i is 1 indexed
        return RCon[i - 1];

//Our team could not work out how to get the values for Rcon when we reached iteration 36 and iteration 40.
//We know it is something to do with multiplication but we could not make 2^8 become 1b000000

//        String[] rconResult = new String[]{
//                "00","00","00","00"
//        };
//
//        //Rcon[i]=[ xi-1,{ 00},{00},{00}], x=2
//        int x = 2;
//        //Nope
//        Double powResult = Math.pow(x,i-1);
//        int intResult = powResult.intValue();
//        String intHex = Integer.toHexString(intResult);
//
//        while(intHex.length() != 2) {
//            intHex = 0 + intHex;
//        }
//
//        rconResult[0] = intHex;
//
//        RCon[i] = rconResult;
//
//        return RCon[i];
    }
}
