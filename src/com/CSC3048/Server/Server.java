package com.CSC3048.Server;

import com.CSC3048.Client.ClientDigitalCertificate;
import com.CSC3048.EncryptionAlgorithms.DigitalSignatureService;
import com.CSC3048.EncryptionAlgorithms.RSA.RSAEncryption;
import com.CSC3048.EncryptionAlgorithms.RSA.RSAKey;
import com.CSC3048.Logging.SecureLog;
import com.CSC3048.TTP.DigitalCertificate;
import com.CSC3048.Utils.StandardMessage;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Date;

public class Server extends JFrame {
    private SecureLog log;
    private JTextArea outputArea;
    private ServerSocket serverSocket;
    private String identificationInformation;
    private StandardMessage certificateMessage;
    private final long TEN_MINUTES = 600000;
    private DigitalSignatureService digitalSignatureService = new DigitalSignatureService();
    private DigitalCertificate serverDigitalCertificate = new ServerDigitalCertificate();
    private ArrayList<UserThread> userThreads = new ArrayList<>();
    private ICredentialManager credentialManager = new DiskCredentials();
    private RSAEncryption rsaEncryption = new RSAEncryption(512);
    /**
     * This is kept secret and only the Server should ever know this.
     * If compromised, server will need new certificate and communications are no longer safe.
     */
    private RSAKey privateKey;

    /**
     * The publicly available, well known, public key of the server.
     */
    private RSAKey publicKey;

    public Server() {
        super("Server - Logon application");
        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                System.exit(0);
            }
        });
        try {
            serverSocket = new ServerSocket(7500);
            identificationInformation =
                    serverSocket.getInetAddress().getHostAddress() + ":"
                            + Integer.toString(serverSocket.getLocalPort());
        } catch (IOException e) {
            System.out.println(e);
            System.exit(1);
        }
        // create and add GUI components
        Container c = getContentPane();
        c.setLayout(new FlowLayout());

        // add text output area
        outputArea = new JTextArea(18, 30);
        outputArea.setEditable(false);
        outputArea.setLineWrap(true);
        outputArea.setWrapStyleWord(true);
        outputArea.setFont(new Font("Verdana", Font.BOLD, 11));
        c.add(outputArea);
        c.add(new JScrollPane(outputArea));

        privateKey = rsaEncryption.getPrivateKeyPair();
        publicKey = rsaEncryption.getPublicKeyPair();
        serverDigitalCertificate.setIdentificationInformation(getIdentificationInformation());
        serverDigitalCertificate.setPublicKey(publicKey);
        serverDigitalCertificate =
                digitalSignatureService.submitApplicationToCertificationAuthority(serverDigitalCertificate);

        certificateMessage = new StandardMessage(serverSocket.getLocalPort(), 0, true, serverDigitalCertificate);
        certificateMessage.setDIGITAL_SIGNATURE(
                digitalSignatureService.signMessage(certificateMessage, privateKey));
        //Create Secure log
        log = new SecureLog();
        setSize(400, 320);
        setResizable(false);
        setVisible(true);
        //Used code from http://stackoverflow.com/questions/2442599/how-to-set-jframe-to-appear-centered-regardless-of-the-monitor-resolution
        Dimension dim = Toolkit.getDefaultToolkit().getScreenSize();
        setLocation(dim.width / 2 - this.getSize().width / 2, dim.height / 2 - this.getSize().height / 2);
    }

    private void getConnectionsAndExchangeCertificates() {
        addOutput("The secure server is waiting for client connections...");

        while (true) {
            try {
                Socket socket = serverSocket.accept();
                ObjectInputStream objectInputStream = new ObjectInputStream(socket.getInputStream());
                ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
                SessionKeys sessionKeys = null;

                StandardMessage clientCertificateMessage = (StandardMessage) objectInputStream.readObject();
                if (clientCertificateMessage.isCERTIFICATE()) {
                    boolean verificationResult = digitalSignatureService.verifyCertificate((ClientDigitalCertificate)
                            clientCertificateMessage.getDATA());
                    if (verificationResult) {
                        ClientDigitalCertificate certificate =
                                (ClientDigitalCertificate) clientCertificateMessage.getDATA();
                        //We should now verify the Standard Message to ensure that it wasn't tampered with in transit.
                        boolean messageVerification = digitalSignatureService.verifyStandardMessage(clientCertificateMessage, certificate.getPublicKey());
                        if (messageVerification) {
                            boolean expired = isMessageExpired(clientCertificateMessage.getTIME_TO_LIVE());
                            if (!expired) {
                                objectOutputStream.writeObject(certificateMessage);
                                StandardMessage encryptedSymmetricKey = (StandardMessage) objectInputStream.readObject();
                                String encryptedKey = (String) encryptedSymmetricKey.getDATA();
                                String decryptedKey = rsaEncryption.decrypt(encryptedKey, privateKey);
                                if (decryptedKey.length() > 10) {
                                    //We are using AES
                                    sessionKeys = saveAESSessionKey(certificate.getPublicKey(), decryptedKey);
                                } else {
                                    //We are using SDES
                                    sessionKeys = new SessionKeys(null, decryptedKey, certificate.getPublicKey());
                                }
                                //Spawn user thread to free up Server thread, enabling it to handle more requests
                                UserThread userThread = new UserThread(objectInputStream, objectOutputStream,
                                        sessionKeys, this);
                                userThreads.add(userThread);
                                userThread.start();
                            }
                            continue;
                        }
                        continue;
                    }
                    continue;
                }
            } catch (IOException e) {
                System.out.println(e);
                System.exit(1);
            } catch (ClassNotFoundException e) {
                System.out.println(e);
                System.exit(1);
            }
        }
    }

    /**
     * Method to change the format of the key after transit and save to session variable.
     *
     * @param publicKey    - public key of the client.
     * @param decryptedKey - key to be formatter
     */
    private SessionKeys saveAESSessionKey(RSAKey publicKey, String decryptedKey) {
        String[] x = decryptedKey.split(";");

        String[][] result = new String[x.length][];
        for (int i = 0; i < x.length; i++) {
            result[i] = x[i].split(",");
        }
        return new SessionKeys(result, null, publicKey);
    }

    /**
     * Prevents replay attacks.
     *
     * @param messageCreationTime - Time the standard message was created
     * @return - boolean outlining whether the message has expired.
     */
    public synchronized boolean isMessageExpired(Date messageCreationTime) {
        Date now = new Date();
        if (now.getTime() > messageCreationTime.getTime() + TEN_MINUTES) {
            return true;
        }
        return false;
    }

    public synchronized boolean saveCredentials(String encryptedUsername,
                                                 String encryptedPassword, String keystrokeData) {
        boolean result = credentialManager.addCredentials(encryptedUsername, encryptedPassword, keystrokeData);
        if(!result) {
            addOutput("Client registration failed!");
            return result;
        }
        addOutput("A new client has registered.");
        return result;
    }

    public synchronized boolean checkCredentials(String decryptedUsername, String username, String password, String keystrokeData) {
        boolean result = credentialManager.validCredentials(username, password, keystrokeData);
        if(!result) {
            addOutput("Login details received from client " + decryptedUsername + " are invalid.");
            return result;
        }
        addOutput("Client: " + decryptedUsername + ", has successfully logged in.");
        return result;
    }

    public synchronized void addOutput(String message) {
        outputArea.append(message + "\n");
        outputArea.setCaretPosition(outputArea.getText().length());
        if (!log.write(message)){
            outputArea.append("** LOG FILE HAS BEEN TAMPERED WITH **" + "\n");
            outputArea.setCaretPosition(outputArea.getText().length());
        }
    }

    public synchronized boolean verifyStandardMessage(StandardMessage standardMessage, RSAKey publicKey) {
        return digitalSignatureService.verifyStandardMessage(standardMessage, publicKey);
    }

    public static void main(String[] args) {
        Server server = new Server();
        server.getConnectionsAndExchangeCertificates();
    }

    public String getIdentificationInformation() {
        return identificationInformation;
    }

    public ArrayList<UserThread> getUserThreads() {
        return userThreads;
    }

    public ICredentialManager getCredentialManager() {
        return credentialManager;
    }
}
