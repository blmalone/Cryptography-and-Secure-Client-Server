package com.CSC3048.EncryptionAlgorithms;

public interface IEncryptionAlgorithm {
    String encrypt(String plainText);

    String decrypt(String cipherText);
}
