package com.CSC3048.EncryptionAlgorithms;

import com.CSC3048.EncryptionAlgorithms.AES.AESEncryption;
import com.CSC3048.EncryptionAlgorithms.HA2.HA2Encryption;
import com.CSC3048.EncryptionAlgorithms.RSA.RSAEncryption;
import com.CSC3048.EncryptionAlgorithms.RSA.RSAKey;
import com.CSC3048.EncryptionAlgorithms.RSA.RSASeed;
import com.CSC3048.EncryptionAlgorithms.SDES.SDESEncryption;

public class Main {

    public static void main(String[] args) {
        System.out.println("Starting Encryption tests...");
        //testSDES();
        //testAES();
        testRSA();
        //testHA2();
    }

    private static void testSDES(){
        System.out.println("\n____ Testing Simplified S-DES ____");
        String principleKey = "1111011000"; //Can accept int[] for key also.
        long startTime = System.currentTimeMillis();
        String plainText = "markfrequency";
        System.out.println("\n      Encryption     ");
        System.out.println("Input PlainText: " + plainText);
        SDESEncryption sDes = new SDESEncryption(principleKey);
        String cipherText = sDes.encrypt(plainText);
        System.out.println("Output CipherText: " + cipherText);
        System.out.println("\n      Decryption     ");
        System.out.println("Input CipherText: " + cipherText);
        String unencryptedText = sDes.decrypt(cipherText);
        System.out.println("Output PlainText: " + unencryptedText);
        long stopTime = System.currentTimeMillis();
        long runTime = stopTime - startTime;
        System.out.println("Run time: " + runTime);
    }

    private static void testAES(){
        System.out.println("\n____ Testing AES ____");
        System.out.println("\n      Encryption     ");
        //For AES P=“mark_frequency__”, where the symbol _ denotes space.
        String input = "mark frequency  ";
        System.out.println("Input PlainText: " + input);
        AESEncryption encryption = new AESEncryption();
        String output = encryption.encrypt(input);
        System.out.println("Output CipherText: " + output);
        System.out.println("\n      Decryption     ");
        System.out.println("Input CipherText: " + output);
        String unencryptedText = encryption.decrypt(output);
        System.out.println("Output PlainText: " + unencryptedText);
    }

    private static void testRSA(){
        System.out.println("\n____ Testing Simplified RSA ____");
        String plainText = "markfrequency";
        System.out.println("\n      Encryption     ");
        System.out.println("Input PlainText: " + plainText);
        RSASeed seed = new RSASeed(41,67,83);
        RSAEncryption rsa = new RSAEncryption(seed);
        RSAKey publicKey = rsa.getPublicKeyPair();
        String cipherText = rsa.encrypt(plainText, publicKey);
        System.out.println("Output CipherText: " + cipherText);
        System.out.println("\n      Decryption     ");
        System.out.println("Input CipherText: " + cipherText);
        RSAKey privateKey = rsa.getPrivateKeyPair();
        String unencryptedText = rsa.decrypt(cipherText,privateKey);
        System.out.println("Output PlainText: " + unencryptedText);
    }

    private static void testHA2(){
        System.out.println("\n____ Testing Simplified HA-2 ____");
        String plainText = "markfrequency";
        System.out.println("\n      Hashing     ");
        System.out.println("Input PlainText: " + plainText);
        HA2Encryption test = new HA2Encryption();
        String hashCode = HA2Encryption.hashCode(plainText);
        System.out.println("Output Hash: " + hashCode);
    }

}
