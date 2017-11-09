package com.CSC3048.Client;

import com.CSC3048.Client.KeystrokeDynamics.KeystrokeDynamics;
import com.CSC3048.EncryptionAlgorithms.AES.AESEncryption;
import com.CSC3048.EncryptionAlgorithms.ISymmetricEncryptionAlgorithm;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.util.ArrayList;

public class Client extends JFrame {
    // variables for the GUI components of the game
    Container c;
    JButton logonButton;
    JPasswordField password;
    JTextField username;
    JPanel logonFieldsPanel, logonButtonPanel;
    JLabel usernameLabel, passwordLabel;
    KeystrokeDynamics keystrokeDynamics;
    //Variables for communication
    Socket socket;
    ObjectInputStream objectInputStream;
    ObjectOutputStream objectOutputStream;
    private JButton btnRegister;
    private JPanel establishConnectionPanel, connectionPanelTop, connectionPanelBottom;
    private JLabel serverIpLabel, encryptionMethodLabel, loadingLabel;
    private JTextField ipAddress;
    private JButton establishConnectionBtn;
    private JRadioButton option1, option2;
    private ButtonGroup group;
    private static ImageIcon loadingGif = new ImageIcon("Images/loading.gif");
    private Chat_ClientThread chatClientThread;
    private String identificationInformation;
    private int sourcePortNumber, destinationPortNumber;
    private final  String[][] aesKey = new String[][]{
            {"2b","28","ab","09"},
            {"7e","ae","f7","cf"},
            {"15","d2","15","4f"},
            {"16","a6","88","3c"}
    };
    private ISymmetricEncryptionAlgorithm encryptionAlgorithm = new AESEncryption(aesKey);

    public Client() {
        super("Chat Service - Client");
        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                System.exit(0);
            }
        });
        setUpSecureConnection();
        getConnections();
        chatClientThread = new Chat_ClientThread(this, objectInputStream, objectOutputStream);
        establishConnectionBtn.setEnabled(true);
    }

    private void setUpSecureConnection() {
        // create and add GUI components
        c = getContentPane();
        c.setLayout(new BorderLayout());
        /*
            Setup initial display for server connection.
            Similar procedure to hitting a servers url - Security protocol established
        */
        setTitle("Establish Secure Connection");
        establishConnectionPanel = new JPanel(new GridLayout(3,2,5,0));
        connectionPanelTop = new JPanel(new GridLayout(2,1,5,5));
        connectionPanelBottom = new JPanel(new GridLayout(1,3,5,5));
        serverIpLabel = new JLabel("Connect to server IP: ");
        ipAddress = new JTextField(10);
        ipAddress.setText("127.0.0.1:7500");
        ipAddress.setEditable(false);
        connectionPanelTop.add(serverIpLabel);
        connectionPanelTop.add(ipAddress);

        encryptionMethodLabel = new JLabel("Choose method of Encryption: ");
        option1 = new JRadioButton("AES");
        option2 = new JRadioButton("S-DES");
        RadioButtonActionListener actionListener = new RadioButtonActionListener(this);
        option1.addActionListener(actionListener);
        option1.setSelected(true);
        option2.addActionListener(actionListener);
        group = new ButtonGroup();
        group.add(option1);
        group.add(option2);
        establishConnectionBtn = new JButton("Connect");
        establishConnectionBtn.setEnabled(false);
        establishConnectionBtn.addActionListener(e -> {
            establishConnectionPanel.removeAll();
            establishConnectionPanel.setLayout(new GridBagLayout());
            establishConnectionPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
            loadingLabel = new JLabel(loadingGif, SwingConstants.CENTER);
            establishConnectionPanel.add(loadingLabel);
            c.add(establishConnectionPanel);
            /*
                Perform server connection.
                Setup encrypted channel so that all users communications
                are confidential and maintain integrity during transit.
                This happens once at the start of every session with the server.
             */
            //getConnections();
            chatClientThread.setSymmetricKey(encryptionAlgorithm);
            chatClientThread.start();
            //Open new login window when connection setup.
        });
        connectionPanelBottom.add(option1);
        connectionPanelBottom.add(option2);
        connectionPanelBottom.add(establishConnectionBtn);

        establishConnectionPanel.add(connectionPanelTop);
        establishConnectionPanel.add(encryptionMethodLabel);
        establishConnectionPanel.add(connectionPanelBottom);
        c.add(establishConnectionPanel);

        setSize(500,125);
        //setResizable(false);
        setVisible(true);

        //Used code from http://stackoverflow.com/questions/2442599/how-to-set-jframe-to-appear-centered-regardless-of-the-monitor-resolution
        Dimension dim = Toolkit.getDefaultToolkit().getScreenSize();
        setLocation(dim.width/2-this.getSize().width/2, dim.height/2-this.getSize().height/2);
    }

    public void showRegisterAndLoginScreen() {
        setVisible(true);
        // GUI components for the username
        logonFieldsPanel = new JPanel();
        logonFieldsPanel.setLayout(new GridLayout(2,2,5,5));
        usernameLabel = new JLabel("Enter Username: ");
        logonFieldsPanel.add(usernameLabel);
        username = new JTextField(10);
        logonFieldsPanel.add(username);

        // GUI components for the password
        passwordLabel = new JLabel("Enter Password: ");
        logonFieldsPanel.add(passwordLabel);
        password = new JPasswordField(10);
        keystrokeDynamics = new KeystrokeDynamics();
        password.addKeyListener(keystrokeDynamics);

        logonFieldsPanel.add(password);
        c.removeAll();
        c.add(logonFieldsPanel,BorderLayout.CENTER);

        // panel for the logon button
        logonButtonPanel = new JPanel();
        logonButton = new JButton("Logon");
        LoginActionListener loginActionListener = new LoginActionListener(this, chatClientThread);
        logonButton.addActionListener(loginActionListener);
        logonButtonPanel.add(logonButton);
        c.add(logonButtonPanel, BorderLayout.SOUTH);

        btnRegister = new JButton("Register");
        Client client = this;
        btnRegister.addActionListener(e -> {
            setVisible(false);
            new Register(client, chatClientThread).setVisible(true);
        });
        logonButtonPanel.add(btnRegister);
        c.validate(); //Refreshes after removeAll() performed.
    }

    void setUpChatClient(boolean chatting) {
        c.remove(logonButtonPanel);
        c.remove(logonFieldsPanel);

        if(!chatting)
            // if the user has not logged on an error message will be displayed
            c.add(new JTextArea("Logon unsuccessful"));
        else
        {	// if the user has logged on the message service GUI will be set up
            c.add(new JTextArea("Logon successful"));
        }

        setResizable(false);
        setVisible(true);

        //Used code from http://stackoverflow.com/questions/2442599/how-to-set-jframe-to-appear-centered-regardless-of-the-monitor-resolution
        Dimension dim = Toolkit.getDefaultToolkit().getScreenSize();
        setLocation(dim.width/2-this.getSize().width/2, dim.height/2-this.getSize().height/2);
    }

    void getConnections() {
        try {
            socket = new Socket(InetAddress.getLocalHost(), 7500);
            identificationInformation = socket.getLocalAddress().getHostAddress() + ":" + Integer.toString(socket.getLocalPort());
            sourcePortNumber = socket.getLocalPort();
            destinationPortNumber = socket.getPort();
            objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
            objectInputStream = new ObjectInputStream(socket.getInputStream());
        }
        catch (IOException e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }
    }

    void closeStreams() {
        try {
            objectInputStream.close();
            objectOutputStream.close();
            socket.close();
        }
        catch (IOException e) {
            System.out.println("Error closing streams" + e);
            System.exit(1);
        }
    }

    public void setSymmetricEncryption(ISymmetricEncryptionAlgorithm encryptionAlgorithm) {
        this.encryptionAlgorithm = encryptionAlgorithm;
    }

    public ISymmetricEncryptionAlgorithm getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }

    public String getIdentificationInformation() {
        return identificationInformation;
    }

    public int getSourcePortNumber() {
        return sourcePortNumber;
    }

    public int getDestinationPortNumber() {
        return destinationPortNumber;
    }

    public static void main(String args[]) {
        Client client = new Client();
    }

    public void resetKeystrokeDynamics() {
        keystrokeDynamics.reset();
    }
}
