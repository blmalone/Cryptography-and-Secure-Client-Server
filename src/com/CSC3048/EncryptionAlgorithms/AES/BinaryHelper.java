package com.CSC3048.EncryptionAlgorithms.AES;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class BinaryHelper {
    public String HexBinaryMultiplication(String hexValueOne, String hexValueTwo) {
        int intValueOne = Integer.parseInt(hexValueOne, 16);
        int intValueTwo = Integer.parseInt(hexValueTwo, 16);

        String binValueOne = Integer.toBinaryString(intValueOne);
        String binValueTwo = Integer.toBinaryString(intValueTwo);

        //Get the positions of the 1's in the binary strings
        List<Integer> valueOnePositions = FindOnePositions(binValueOne);
        List<Integer> valueTwoPositions = FindOnePositions(binValueTwo);

        //Expand the brackets. Everything item in one added to every item in two
        List<Integer> expandedBrackets = new ArrayList<>();
        for(int valueOnePosition : valueOnePositions) {
            //add to and store in new array
            for(int valueTwoPosition : valueTwoPositions) {
                expandedBrackets.add(valueOnePosition + valueTwoPosition);
            }
        }

        //If a duplicate exists remove all existence of it from the collection
        List<Integer> expandedBracketsDupsRemoved = new ArrayList<>();
        for(int expandedBracket : expandedBrackets) {
            if(expandedBracketsDupsRemoved.contains(expandedBracket)) {
                expandedBracketsDupsRemoved.remove((Object)expandedBracket);
            } else {
                expandedBracketsDupsRemoved.add(expandedBracket);
            }
        }

        //Converted the expanded brackets with no dups to a binary string
        Collections.sort(expandedBracketsDupsRemoved);
        int largestBinaryPositionIndex = expandedBracketsDupsRemoved.size() - 1;
        int largestBinaryPosition = 0;
        if(largestBinaryPositionIndex > 0) {
            largestBinaryPosition = expandedBracketsDupsRemoved.get(largestBinaryPositionIndex);
        }

        String resultingBinaryString = "";

        for(int i = 0; i < largestBinaryPosition; i++) {
            if(expandedBracketsDupsRemoved.contains(i)) {
                resultingBinaryString = "1" + resultingBinaryString;
            } else {
                resultingBinaryString = "0" + resultingBinaryString;
            }
        }

        if(resultingBinaryString.length() > 0) {
            //This is because we did not add the 1 at the starting pos
            resultingBinaryString = "1" + resultingBinaryString;
        }

        //get binary string of irreducible polynomial
        String irreduciblePolynomial = "011b";
        int irreduciblePolynomialDec = Integer.parseInt(irreduciblePolynomial,16);
        String irreduciblePolynomialBin = Integer.toBinaryString(irreduciblePolynomialDec);

        //Do binary division of irreducible polynomial until we have a remainder (lengths don't match?)
        String remainderBinaryString = resultingBinaryString;
        while (remainderBinaryString.length() >= irreduciblePolynomialBin.length()) {
            StringBuilder newRemainderBinaryString = new StringBuilder(remainderBinaryString);

            //Start from the left (Most Sig Bit)
            for(int i = 0; i < irreduciblePolynomialBin.length(); i++) {
                char irreductiblePolynomialPos = irreduciblePolynomialBin.charAt(i);
                char remainderBinPos = newRemainderBinaryString.charAt(i);

                if(irreductiblePolynomialPos == remainderBinPos) {
                    newRemainderBinaryString.setCharAt(i,'0');
                } else {
                    newRemainderBinaryString.setCharAt(i, '1');
                }
            }

            remainderBinaryString = newRemainderBinaryString.toString();
            //Left replace
            remainderBinaryString = remainderBinaryString.replaceFirst("^0+(?!$)", "");
        }

        if(remainderBinaryString == "") {
            return "00";
        }

        //Convert the remainder into Hex
        int remainderDecString = Integer.parseInt(remainderBinaryString, 2);
        String remainderHexString = Integer.toHexString(remainderDecString);

        if(remainderHexString.length() != 2) {
            remainderHexString = "0" + remainderHexString;
        }

        return remainderHexString;
    }

    private ArrayList<Integer> FindOnePositions(String binaryValue) {
        ArrayList<Integer> positions = new ArrayList<>();

        char[] binaryArray = binaryValue.toCharArray();
        for(int i = 0; i < binaryArray.length; i++) {
            if(binaryArray[i] == '1') {
                positions.add((binaryArray.length - i) - 1);
            }
        }

        return positions;
    }

    /**
     * The binary multiplication will either be by 1, 2 or 3
     * @param multiplyBy - will either be 1, 2 or 3
     * @param hexString input binary
     * @return - The result of the binary multiplication
     */
    public String binaryMultiplication(int multiplyBy, String hexString) {
        if(hexString == null) {
            return null;
        }
        //convert s to binary
        int decString = Integer.parseInt(hexString, 16);
        String binaryString = Integer.toBinaryString(decString);

        //The toBinaryString method will leave off the left most bit if it's zero
        while(binaryString.length() != 8) {
            binaryString = 0 + binaryString;
        }

        //i will be 1 2 or 3
        if(multiplyBy == 1) {
            return binaryString;
        }

        //If leftmost bit is zero shift left
        //If leftmost bit is one shift left and xor with 00011011
        String resultBinary = "";

        String firstChar = binaryString.substring(0,1);

        if(firstChar.equals("0")) {
            resultBinary = rotateLeft(binaryString);
        } else {
            String rotatedInt = rotateLeft(binaryString);
            resultBinary = xor(rotatedInt,"00011011");
        }

        if(multiplyBy == 2) {
            //convert back to hex
            return resultBinary;
        }

        if(multiplyBy == 3) {
            return xor(resultBinary, binaryString);
        }

        return null;
    }

    /**
     * Rotates the bytes to the left by 1 and adds a zero to the end
     * @param binaryString - String to rotate
     * @return - rotated string
     */
    private String rotateLeft(String binaryString) {
        String result = binaryString.substring(1, binaryString.length());
        result += 0;
        return result;
    }

    /**
     * Performs an exclusive or operation on two binary strings
     * @param one - binary string one
     * @param two - binary string two
     * @return - the result of the XOR operation
     */
    public String xor(String one, String two) {
        if(one == null || two == null) {
            return null;
        }

        String result = "";
        char[] oneCharArray = one.toCharArray();
        char[] twoCharArray = two.toCharArray();
        for(int i = 0; i < one.length(); i++) {
            if(oneCharArray[i] == twoCharArray[i]) {
                result += 0;
            } else {
                result += 1;
            }
        }

        return result;
    }
}
