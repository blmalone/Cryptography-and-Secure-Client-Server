import java.util.Arrays;
import java.util.Random;

/**
 * For S-DES the output should be bytes in binary form
 * <p>
 * Principle Key is 1111011000
 * <p>
 * Use the ASCII binary encoding of each letter
 * <p>
 * Input plaintext is P = "markfrequency"
 * The plaintext can be passed as a commandline arg or hardcoded
 */
public class SDESEncryption implements ISymmetricEncryptionAlgorithm {

    /**
     * Standard permutations starting values are one less because we are working
     * with indexes that start at 0. Still achieves the same result.
     */
    private final int[] standardPermutationP10 = {2, 4, 1, 6, 3, 9, 0, 8, 7, 5};
    private final int[] standardPermutationP8 = {5, 2, 6, 3, 7, 4, 9, 8};
    private final int[] standardInitialPermutation = {1, 5, 2, 0, 3, 7, 4, 6};
    private final int[] standardExpansionPermutation = {3, 0, 1, 2, 1, 2, 3, 0};
    private final int[] standardPermutationP4 = {1, 3, 2, 0};
    private final int[] standardFinalPermutationIP = {3, 0, 2, 4, 6, 1, 7, 5};
    private final int[][] s0 = {
            {1, 0, 3, 2},
            {3, 2, 1, 0},
            {0, 2, 1, 3},
            {3, 1, 3, 2}
    };
    private final int[][] s1 = {
            {0, 1, 2, 3},
            {2, 0, 1, 3},
            {3, 0, 1, 0},
            {2, 1, 0, 3}
    };
    private int[] subKey1;
    private int[] subKey2;
    private String principleKey;

    public SDESEncryption(String principleKey) {
        this.principleKey = principleKey;
        int[] currentPrincipleKey = new int[10];

        for (int i = 0; i < currentPrincipleKey.length; i++) {
            currentPrincipleKey[i] = Integer.parseInt(Character.toString(principleKey.charAt(i)));
        }
        generateK1AndK2(currentPrincipleKey);
    }

    public SDESEncryption(int[] principleKey) {
        symmetricKeyToString(principleKey);
        //Initialise Key1 and Key2
        generateK1AndK2(principleKey);
    }

    /**
     * Creating an SDESEncryption object without specifying the principle key will result in
     * a random symmetric key being generated.
     */
    public SDESEncryption() {
        int[] principleKey = generatePrincipleKey();
        symmetricKeyToString(principleKey);
        generateK1AndK2(principleKey);
    }

    private int[] generatePrincipleKey(){
        int[] currentPrincipleKey = new int[10];
        Random random = new Random();
        for(int i = 0; i<currentPrincipleKey.length; i++) {
            currentPrincipleKey[i] = random.nextInt((1 - 0) + 1) + 0;
        }
        return currentPrincipleKey;
    }

    /**
     * Encrypts plaintext to cipher text using the standard simplified DES algorithm
     * @param plainText - String to be encrypted
     * @return - Ciphertext String
     */
    @Override
    public String encrypt(String plainText) {
        //Break plaintext up into blocks
        int[][] blocks = new int[plainText.length()][];
        for (int i = 0; i < plainText.length(); i++) {
            int blockDecimal = (int) plainText.charAt(i);
            blocks[i] = decimalToBinary(blockDecimal, 8);
        }
        return sDesAlgorithm(blocks, subKey1, subKey2, false);
    }

    /**
     * Decrypts ciphertext to plaintext using the standard simplified DES algorithm.
     * This method performs the same steps as encryption only using the sub-keys in reverse order.
     * K2 first then K1.
     * @param cipherText - String to be decrypted
     * @return - Plaintext String
     */
    @Override
    public String decrypt(String cipherText) {
        cipherText = cipherText.replace(" ", "");
        int[][] blocks = generateBlocks(cipherText);
        return sDesAlgorithm(blocks, subKey2, subKey1, true);
    }

    private int[][] generateBlocks(String text) {
        char[] charArray = text.toCharArray();
        int[][] result = new int[charArray.length/8][];
        int firstElement = 0, lastElement = 7;
        for (int i = 0; i < result.length; i++) {
            result[i] = getBlock(charArray, firstElement, lastElement);
            firstElement = firstElement + 8;
            lastElement = lastElement + 8;
        }
        return result;
    }

    private int[] getBlock(char[] charArray, int firstElement, int lastElement) {
        int[] block = new int[8];
        for (int i = firstElement, j = 0; i < lastElement+1; i++, j++) {
            block[j] = Integer.parseInt(String.valueOf(charArray[i]));
        }
        return block;
    }

    /**
     * Common operations to both encryption and decryption. Ordering of sub-keys
     * distinguishes between each.
     * @param blocks - Will either be encrypted or decrypted, individual units that are operated on in groups
     * @param firstSubKey - key to be used in the first functionK
     * @param secondSubKey - key to be used in the second functionK
     * @param isDecryption - if this flag is set to true, return result as ascii characters
     * @return - Encrypted or decrypted text
     */
    private String sDesAlgorithm(final int[][] blocks, final int[] firstSubKey, final int[] secondSubKey,
                                 final boolean isDecryption) {
        StringBuilder stringBuilder = new StringBuilder();
        //Perform initial permutation on the first block of plaintext. i.e. the first letter (8-bits)
        for (int i = 0; i < blocks.length; i++) {
            blocks[i] = initialPermutation(blocks[i]);
            //Split block into 4 left and right most bits
            int[] leftMostBits = Arrays.copyOfRange(blocks[i], 0, blocks[i].length / 2);
            int[] rightMostBits = Arrays.copyOfRange(blocks[i], blocks[i].length / 2, blocks[i].length);

            blocks[i] = functionK(leftMostBits, rightMostBits, firstSubKey);

            int[] switchedBits = switchBits(blocks[i]);
            leftMostBits = Arrays.copyOfRange(switchedBits, 0, 4);
            rightMostBits = Arrays.copyOfRange(switchedBits, 4, 8);

            blocks[i] = functionK(leftMostBits, rightMostBits, secondSubKey);

            //Final Permutation
            int[] cipher = finalPermutation(blocks[i]);
            stringBuilder.append(generateOutput(isDecryption, cipher));
        }
        return stringBuilder.toString();
    }

    /**
     * This method generates the output representation depending upon whether encryption or decryption is performed.
     * @param isDecryption
     * @param cipher - text to be formatted
     * @return - output text from the S-DES algorithm
     */
    private String generateOutput(final boolean isDecryption, final int[] cipher) {
        StringBuilder strB = new StringBuilder();
        if(isDecryption) {
            for (int value : cipher) {
                strB.append(value);
            }
            char c = (char) Integer.parseInt(strB.toString(), 2);
            return String.valueOf(c);
        } else {
            for (int value : cipher) {
                strB.append(value);
            }
            return strB.toString() + " ";
        }
    }

    /**
     * Switch function (SW) interchanges the left and right 4 bits so that second instance of
     * fK operates on a different 4 bits
     *
     * @param bitsToSwitch - input
     * @return - result of switch
     */
    private int[] switchBits(int[] bitsToSwitch) {
        int[] result = new int[8];
        result[0] = bitsToSwitch[4];
        result[1] = bitsToSwitch[5];
        result[2] = bitsToSwitch[6];
        result[3] = bitsToSwitch[7];
        result[4] = bitsToSwitch[0];
        result[5] = bitsToSwitch[1];
        result[6] = bitsToSwitch[2];
        result[7] = bitsToSwitch[3];
        return result;
    }

    /**
     * Combination of permutation and substitution
     * functions.
     *
     * @param leftMostBits  - of the initial permutation
     * @param rightMostBits - of the initial permutation
     * @param key
     * @return
     */
    private int[] functionK(int[] leftMostBits, int[] rightMostBits, int[] key) {

        int[] result = new int[8];
        //Perform large F function to produce 4 bits
        int[] functionFResult = functionF(rightMostBits, key);

        int[] firstFourBits = xor(functionFResult, leftMostBits, 4);

        System.arraycopy(firstFourBits, 0, result, 0, firstFourBits.length);
        System.arraycopy(rightMostBits, 0, result, firstFourBits.length, rightMostBits.length);

        return result;
    }

    /**
     * Produces 4-bits after a series of operations on right most bits.
     *
     * @param rightMostBits - of the initial permutation
     * @param key           - sub-key used in the function
     * @return 4-bit int array
     */
    private int[] functionF(int[] rightMostBits, int[] key) {
        int[] expandedRightMostBits = expansionPermutation(rightMostBits);
        int[] exclusiveOrWithKey = xor(expandedRightMostBits, key, 8);

        //Perform Mapping
        return mappingF(exclusiveOrWithKey);
    }

    /**
     * Performs the mapping of the LMBs and RMBs for functionF.
     * S-Boxes used for substitution.
     *
     * @param exclusiveOrWithKey - result from previous step of functionF
     * @return - 4-bit value
     */
    private int[] mappingF(int[] exclusiveOrWithKey) {
        int[] mapping = new int[4];
        //First 4 bits
        int row = (exclusiveOrWithKey[0] * 2) + exclusiveOrWithKey[3];
        int col = (exclusiveOrWithKey[1] * 2) + exclusiveOrWithKey[2];
        int valueS0 = s0[row][col];
        int[] firstTwoBits = decimalToBinary(valueS0, 2);

        //Last 4 bits
        row = (exclusiveOrWithKey[4] * 2) + exclusiveOrWithKey[7];
        col = (exclusiveOrWithKey[5] * 2) + exclusiveOrWithKey[6];
        int valueS1 = s1[row][col];
        int[] lastTwoBits = decimalToBinary(valueS1, 2);

        System.arraycopy(firstTwoBits, 0, mapping, 0, firstTwoBits.length);
        System.arraycopy(lastTwoBits, 0, mapping, firstTwoBits.length, lastTwoBits.length);

        return permutation4(mapping);
    }

    private int[] permutation4(int[] mapping) {
        int[] temp = new int[4];
        for (int i = 0; i < mapping.length; i++) {
            temp[i] = mapping[standardPermutationP4[i]];
        }
        return temp;
    }

    /**
     * Exclusive OR operation performed with operands of a given fixed length
     *
     * @param firstOperand
     * @param secondOperand
     * @return - the XOR result
     */
    private int[] xor(int[] firstOperand, int[] secondOperand, int bitLength) {
        int[] result = new int[bitLength];
        for (int i = 0; i < firstOperand.length; i++) {
            result[i] = firstOperand[i] ^ secondOperand[i];
        }
        return result;
    }

    /**
     * Expands right most bits from 4 to 8 bit values.
     *
     * @param rightMostBits - of the initial permutation
     * @return - expanded right most bits
     */
    private int[] expansionPermutation(int[] rightMostBits) {
        int[] temp = new int[8];
        for (int i = 0; i < temp.length; i++) {
            temp[i] = rightMostBits[standardExpansionPermutation[i]];
        }
        return temp;
    }

    /**
     * The final permutation used on a block before cipher text is produced
     *
     * @param - bits to undergo the final permutation
     * @return - cipher
     */
    private int[] finalPermutation(int[] finalPermutation) {
        int[] temp = new int[8];
        for (int i = 0; i < temp.length; i++) {
            temp[i] = finalPermutation[standardFinalPermutationIP[i]];
        }
        return temp;
    }

    public void generateK1AndK2(int[] principleKey) {
        int[] p10ShiftKey = initialCommonSteps(principleKey);

        subKey1 = generateK1(p10ShiftKey);
        subKey2 = generateK2(p10ShiftKey);
    }

    /**
     * Generate K2 from the 10bit shift(p10(k)) result.
     * The input will undergo a further two shift operations, (total of three)
     * then a final standard permutation8 operation is applied.
     * This will output an 8bit result as we undergo a contraction permutation.
     */
    private int[] generateK2(int[] p10shiftKey) {
        int[] p10shift3Key = shift(p10shiftKey, 2);
        return permutation8(p10shift3Key);
    }

    /**
     * Steps common to the generation of sub-keys 1 and 2.
     *
     * @param principleKey - initial principle key
     * @return shift(p10(K))
     */
    private int[] initialCommonSteps(int[] principleKey) {
        int[] p10Key = permutation10(principleKey);
        return shift(p10Key, 1);
    }

    /**
     * Generate K1 from the 10bit shift(p10(k)) result.
     * This will output an 8bit result as we undergo a contraction permutation.
     */
    private int[] generateK1(int[] p10ShiftKey) {
        return permutation8(p10ShiftKey);
    }

    /**
     * Performs the standard permutation10 operation on the principle key.
     *
     * @param principleKey - initial key
     * @return - result of permutation
     */
    private int[] permutation10(int[] principleKey) {
        int[] temp = new int[10];
        for (int i = 0; i < principleKey.length; i++) {
            temp[i] = principleKey[standardPermutationP10[i]];
        }
        return temp;
    }

    /**
     * Performs a contraction permutation on the 10-bit param
     * to produce an 8-bit key
     *
     * @param key - 10-bit key
     * @return - new 8-bit key
     */
    private int[] permutation8(int[] key) {
        int[] temp = new int[8];
        for (int i = 0; i < temp.length; i++) {
            temp[i] = key[standardPermutationP8[i]];
        }
        return temp;
    }

    private int[] initialPermutation(int[] block) {
        int[] temp = new int[8];
        for (int i = 0; i < temp.length; i++) {
            temp[i] = block[standardInitialPermutation[i]];
        }
        return temp;
    }


    /**
     * Shifts the left most 5 bits by one position to the left.
     * Shifts the right most 5 bits by one position to the left.
     * The shift operation is circular.
     *
     * @param p10Key       - the permuted principle key
     * @param timesToShift - the amount of times to shift the bits to the left.
     * @return - result of shifting bits.
     */
    private int[] shift(int[] p10Key, int timesToShift) {
        for (int j = 0; j < timesToShift; j++) {
            //shift the LMSB to left
            int firstLeftMostElement = p10Key[0];
            for (int i = 0; i < (p10Key.length / 2) - 1; i++) {
                p10Key[i] = p10Key[i + 1];
            }
            p10Key[(p10Key.length / 2) - 1] = firstLeftMostElement;
        }

        for (int j = 0; j < timesToShift; j++) {
            //shift the RMSB to left once
            int firstRightMostElement = p10Key[(p10Key.length / 2)];
            for (int i = 5; i < p10Key.length - 1; i++) {
                p10Key[i] = p10Key[i + 1];
            }
            p10Key[p10Key.length - 1] = firstRightMostElement;
        }
        return p10Key;
    }

    /**
     * Method to to convert the characters decimal representation to a specific block length in binary format.
     *
     * @param decimalNumber - decimal representation of character that constitutes a block
     * @return - int array i.e. the block to be worked on.
     */
    private static int[] decimalToBinary(int decimalNumber, int binaryLength) {
        int[] result = new int[binaryLength];
        for (int i = result.length - 1; i >= 0; i--) {
            int binary = decimalNumber % 2;
            if (binary == 1)
                decimalNumber = (decimalNumber - 1) / 2;
            else
                decimalNumber = decimalNumber / 2;
            result[i] = binary;
        }
        return result;
    }

    private void symmetricKeyToString(int[] principleKey) {
        StringBuilder strB = new StringBuilder();
        for(int i: principleKey) {
            strB.append(Integer.toString(i));
        }
        this.principleKey = strB.toString();
    }

    public String getSymmetricKey() {
        return principleKey;
    }
}