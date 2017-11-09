package com.CSC3048.EncryptionAlgorithms;

public interface ISymmetricEncryptionAlgorithm {
    String encrypt(String plainText);

    String decrypt(String cipherText);

    String getSymmetricKey();
}
