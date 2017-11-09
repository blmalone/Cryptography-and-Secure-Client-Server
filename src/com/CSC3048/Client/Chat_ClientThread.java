package com.CSC3048.Client;

import com.CSC3048.EncryptionAlgorithms.DigitalSignatureService;
import com.CSC3048.EncryptionAlgorithms.ISymmetricEncryptionAlgorithm;
import com.CSC3048.EncryptionAlgorithms.RSA.RSAEncryption;
import com.CSC3048.EncryptionAlgorithms.RSA.RSAKey;
import com.CSC3048.Server.ServerDigitalCertificate;
import com.CSC3048.TTP.DigitalCertificate;
import com.CSC3048.Utils.StandardMessage;

import javax.swing.*;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Date;

class Chat_ClientThread extends Thread {

    private Client client;
    private ObjectInputStream threadInputStream;
    private ObjectOutputStream threadOutputStream;
    private DigitalSignatureService digitalSignatureService = new DigitalSignatureService();
    private RSAEncryption rsaEncryption = new RSAEncryption(512);
    private ISymmetricEncryptionAlgorithm encryptionAlgorithm = null;
    private DigitalCertificate clientDigitalCertificate = new ClientDigitalCertificate();
    private StandardMessage certificateMessage, symmetricKeyMessage;
    private RSAKey serverPublicKey;
    private final long TEN_MINUTES = 600000;
    private boolean connected = false;
    private static int attempts = 0;

    /**
     * This is kept secret and only the Client should ever know this.
     * If compromised, client will need new certificate and communications are no longer safe.
     */
    private RSAKey privateKey;

    /**
     * The publicly available, well known, public key of the client.
     */
    private RSAKey publicKey;

    public Chat_ClientThread(Client client, ObjectInputStream in, ObjectOutputStream out) {
        this.client = client;
        threadInputStream = in;
        threadOutputStream = out;
        privateKey = rsaEncryption.getPrivateKeyPair();
        publicKey = rsaEncryption.getPublicKeyPair();

        clientDigitalCertificate.setIdentificationInformation(client.getIdentificationInformation());
        clientDigitalCertificate.setPublicKey(publicKey);
        clientDigitalCertificate =
                digitalSignatureService.submitApplicationToCertificationAuthority(clientDigitalCertificate);
    }

    public void run() {
        try {
            certificateMessage = new StandardMessage(client.getSourcePortNumber(),
                    client.getDestinationPortNumber(), true, clientDigitalCertificate);
            //Every Message sent to the server will have a digital signature regardless if it has a certificate body.
            certificateMessage.setDIGITAL_SIGNATURE(
                    digitalSignatureService.signMessage(certificateMessage, privateKey));
            //Send client certificate to the server.
            threadOutputStream.writeObject(certificateMessage);

            //Read certificate obj from server
            StandardMessage serverCertificateMessage = (StandardMessage) threadInputStream.readObject();
            validateCertificate(serverCertificateMessage);

            sendSymmetricKey();

            connected = true;
            //Open the login/register window
            client.showRegisterAndLoginScreen();

            while (connected) {
            }

            //client.closeStreams();
        } catch (IOException e) {
            System.out.println("Error in the run method first catch " + e);
            System.exit(1);
        } catch (ClassNotFoundException e) {
            System.out.println("Run catch 2 " + e);
            System.exit(1);
        }
    }

    private void sendSymmetricKey() throws IOException {
        ISymmetricEncryptionAlgorithm encryptionAlgorithm = client.getEncryptionAlgorithm();
        //Encrypt with the trusted rsa public key of server so it can be decrypted by the server only
        String encryptedSymmetricKey = rsaEncryption.encrypt(encryptionAlgorithm.getSymmetricKey(), serverPublicKey);
        symmetricKeyMessage = new StandardMessage(client.getSourcePortNumber(),
                client.getDestinationPortNumber(), true, encryptedSymmetricKey);
        symmetricKeyMessage.setDIGITAL_SIGNATURE(
                digitalSignatureService.signMessage(symmetricKeyMessage, privateKey));
        //Send symmetric to the server
        threadOutputStream.writeObject(symmetricKeyMessage);
    }

    private void validateCertificate(StandardMessage serverCertificateMessage) throws IOException, ClassNotFoundException {
        if (serverCertificateMessage.isCERTIFICATE()) {
            boolean verificationResult = digitalSignatureService.verifyCertificate((ServerDigitalCertificate)
                    serverCertificateMessage.getDATA());
            if (verificationResult) {
                ServerDigitalCertificate certificate =
                        (ServerDigitalCertificate) serverCertificateMessage.getDATA();
                serverPublicKey = certificate.getPublicKey();
                boolean messageVerification = digitalSignatureService.verifyStandardMessage(serverCertificateMessage,
                        serverPublicKey);
                if (messageVerification) {
                    boolean expired = isMessageExpired(serverCertificateMessage.getTIME_TO_LIVE());
                    if (!expired) {
                        return;
                    }
                    System.out.println("The message received has expired. Connection terminated");
                    System.exit(0);
                }
                System.out.println("The message received looks to have been changed in transit. Connection terminated");
                System.exit(0);
            }
            System.out.println("The certificate was not issued by the CA. Connection terminated");
            System.exit(0);
        }
        System.out.println("Expected a certificate message as first communication. Connection terminated");
        System.exit(0);
    }

    /**
     * Will send message to party once secure communication channel has been established.
     * Encrypts and signs every message to the peer
     */
    private void send(StandardMessage standardMessage) {

    }

    public Boolean sendRegisterDetails(String username, String password, ArrayList<Long> averageKeystrokeData) throws ClassNotFoundException {
        try {
            String encryptedUsername = encryptionAlgorithm.encrypt(username);
            String encryptedPassword = encryptionAlgorithm.encrypt(password);
            String keyStrokeText = convertKeyStrokeData(averageKeystrokeData);
            String encryptedKeyStrokes = encryptionAlgorithm.encrypt(keyStrokeText);
            String encryptedCredentialsType = encryptionAlgorithm.encrypt("true");
            Credentials registerCredentials
                    = new Credentials(encryptedUsername, encryptedPassword, encryptedKeyStrokes, encryptedCredentialsType);
            StandardMessage secureMessage = new StandardMessage(client.getSourcePortNumber(),
                    client.getDestinationPortNumber(), true, registerCredentials);
            secureMessage.setDIGITAL_SIGNATURE(
                    digitalSignatureService.signMessage(secureMessage, privateKey));
            threadOutputStream.writeObject(secureMessage);
            return (Boolean) threadInputStream.readObject();
        } catch (IOException e) {
            System.out.println(e);
            System.exit(1);
        }
        return false;
    }


    public void sendLoginDetails() throws ClassNotFoundException {
        try {
            if(client.password.getText().equals("")) {
                JOptionPane.showMessageDialog(null, "Please enter a password.", null, JOptionPane.ERROR_MESSAGE);
                return;
            }
            Boolean loggedIn = false;
            if(!loggedIn || attempts < 3) {
                attempts++;
                String usernameText = client.username.getText();
                String passwordText = client.password.getText();
                ArrayList<Long> keystrokeData = client.keystrokeDynamics.GetAllEvents();
                String encryptedUsername = encryptionAlgorithm.encrypt(usernameText);
                String encryptedPassword = encryptionAlgorithm.encrypt(passwordText);
                String keyStrokeText = convertKeyStrokeData(keystrokeData);
                String encryptedKeyStrokes = encryptionAlgorithm.encrypt(keyStrokeText);
                String encryptedCredentialsType = encryptionAlgorithm.encrypt("false"); //not a register message
                Credentials loginCredentials = new Credentials(encryptedUsername, encryptedPassword, encryptedKeyStrokes, encryptedCredentialsType);
                StandardMessage secureMessage = new StandardMessage(client.getSourcePortNumber(),
                        client.getDestinationPortNumber(), true, loginCredentials);
                secureMessage.setDIGITAL_SIGNATURE(
                        digitalSignatureService.signMessage(secureMessage, privateKey));
                threadOutputStream.writeObject(secureMessage);

                loggedIn = (Boolean) threadInputStream.readObject();
                if (!loggedIn) {
                    client.password.setText("");
                    JOptionPane.showMessageDialog(null, "You have " + (3 - attempts) + " attempts remaining!", null, JOptionPane.ERROR_MESSAGE);
                    if (attempts == 3) {
                        //close connection
                        client.setUpChatClient(loggedIn);
                    }
                } else {
                    client.setUpChatClient(loggedIn);
                }
            }

            client.resetKeystrokeDynamics();

        } catch (IOException e) {
            System.out.println(e);
            System.exit(1);
        }
    }

    public void showLoginScreen() {
        client.showRegisterAndLoginScreen();
    }

    private String convertKeyStrokeData(ArrayList<Long> keystrokeData) {
        String keyStrokeText = "";

        for(Long keystroke : keystrokeData) {
            keyStrokeText += keystroke + ",";
        }

        keyStrokeText = keyStrokeText.substring(0, keyStrokeText.length() - 1);

        return keyStrokeText;
    }

    /**
     * Called when user selects the form of encryption they are using.
     *
     * @param encryptionAlgorithm
     */
    public void setSymmetricKey(ISymmetricEncryptionAlgorithm encryptionAlgorithm) {
        this.encryptionAlgorithm = encryptionAlgorithm;
    }

    /**
     * Prevents replay attacks.
     *
     * @param messageCreationTime - Time the standard message was created
     * @return - boolean outlining whether the message has expired.
     */
    private boolean isMessageExpired(Date messageCreationTime) {
        Date now = new Date();
        if (now.getTime() > messageCreationTime.getTime() + TEN_MINUTES) {
            return true;
        }
        return false;
    }
}
