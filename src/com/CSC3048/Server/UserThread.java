package com.CSC3048.Server;

import com.CSC3048.Client.Credentials;
import com.CSC3048.EncryptionAlgorithms.AES.AESEncryption;
import com.CSC3048.EncryptionAlgorithms.ISymmetricEncryptionAlgorithm;
import com.CSC3048.EncryptionAlgorithms.SDES.SDESEncryption;
import com.CSC3048.Utils.StandardMessage;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class UserThread extends Thread {
    private ObjectInputStream threadInputStream;
    private ObjectOutputStream threadOutputStream;
    private boolean userConnected = true;
    private SessionKeys sessionKeys;
    private Server server;
    private ISymmetricEncryptionAlgorithm encryptionAlgorithm;
    private int loginAttempts = 0;

    public UserThread(ObjectInputStream in, ObjectOutputStream out, SessionKeys sessionKeys, Server server) {
        threadInputStream = in;
        threadOutputStream = out;
        this.sessionKeys = sessionKeys;
        this.server = server;
        if (sessionKeys.getAesSymmetricKey() != null) {
            encryptionAlgorithm = new AESEncryption(sessionKeys.getAesSymmetricKey());
        } else {
            encryptionAlgorithm = new SDESEncryption(sessionKeys.getsDesSymmetricKey());
        }
    }

    public void run() {
        while (userConnected) {
            try {
                getUserCredentials();
            } catch (Exception e) {
                System.out.println("Something went wrong in the server quit" + e);
            }
        }
    }

    private void getUserCredentials() throws IOException, ClassNotFoundException {
        if (loginAttempts < 3) {
            loginAttempts++;
            StandardMessage secureMessage = (StandardMessage) threadInputStream.readObject();
            boolean verificationResult = server.verifyStandardMessage(secureMessage, sessionKeys.getPublicKey());
            boolean expired = server.isMessageExpired(secureMessage.getTIME_TO_LIVE());
            if (verificationResult && !expired) {
                Credentials credentials = (Credentials) secureMessage.getDATA();
                String isRegisterEvent = encryptionAlgorithm.decrypt(credentials.getRegisterMessage());
                if (isRegisterEvent.trim().equals("true")) {
                    //perform register operations
                    loginAttempts = 0;
                    String keyStrokeData = encryptionAlgorithm.decrypt(credentials.getKeystrokeData());
                    server.saveCredentials(credentials.getUsername(), credentials.getPassword(), keyStrokeData);
                    threadOutputStream.writeObject(true);
                } else {
                    //perform login operations
                    String keyStrokeData = encryptionAlgorithm.decrypt(credentials.getKeystrokeData());
                    String decryptedUsername = encryptionAlgorithm.decrypt(credentials.getUsername());
                    decryptedUsername = decryptedUsername.trim();
                    boolean validCreds = server.checkCredentials(decryptedUsername, credentials.getUsername(), credentials.getPassword(), keyStrokeData);
                    threadOutputStream.writeObject(validCreds);
                    if (validCreds) {
                        loginAttempts = 0;
                    }
                }
            }
        } else {
            //Too many attempts to access account.
            threadOutputStream.close();
            threadInputStream.close();
            server.getUserThreads().remove(this);
        }
    }
}
