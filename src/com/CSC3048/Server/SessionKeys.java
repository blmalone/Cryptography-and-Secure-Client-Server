package com.CSC3048.Server;

import com.CSC3048.EncryptionAlgorithms.RSA.RSAKey;

public class SessionKeys {

    private String[][] aesSymmetricKey;
    private String sDesSymmetricKey;
    private RSAKey publicKey;
    private boolean isAES = false;

    public SessionKeys(String[][] aesSymmetricKey, String sDesSymmetricKey, RSAKey publicKey) {
        if (sDesSymmetricKey == null) {
            isAES = true;
        }
        this.aesSymmetricKey = aesSymmetricKey;
        this.sDesSymmetricKey = sDesSymmetricKey;
        this.publicKey = publicKey;
    }

    public String[][] getAesSymmetricKey() {
        return aesSymmetricKey;
    }

    public void setAesSymmetricKey(String[][] aesSymmetricKey) {
        this.aesSymmetricKey = aesSymmetricKey;
    }

    public String getsDesSymmetricKey() {
        return sDesSymmetricKey;
    }

    public void setsDesSymmetricKey(String sDesSymmetricKey) {
        this.sDesSymmetricKey = sDesSymmetricKey;
    }

    public RSAKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(RSAKey publicKey) {
        this.publicKey = publicKey;
    }

    public boolean isAES() {
        return isAES;
    }

    public void setAES(boolean AES) {
        isAES = AES;
    }
}
