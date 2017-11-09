package com.CSC3048.Client.KeystrokeDynamics;

import javax.swing.*;
import java.awt.*;

public class KeystrokeDynamicsGUI extends JFrame{
    Container c;
    JPasswordField password;
    JButton logonButton;
    JPanel logonFieldsPanel, logonButtonPanel;
    JLabel passwordLabel;
    KeystrokeDynamicsButtonHandler bHandler;
    KeystrokeDynamics keystrokeDynamics;

    public void startTestGUI() {
        // create and add GUI components
        c = getContentPane();
        c.setLayout(new BorderLayout());

        // GUI components for the username
        logonFieldsPanel = new JPanel();
        logonFieldsPanel.setLayout(new GridLayout(2,2,5,5));
        // GUI components for the password
        passwordLabel = new JLabel("Enter Password: ");
        logonFieldsPanel.add(passwordLabel);
        password = new JPasswordField(10);
        keystrokeDynamics = new KeystrokeDynamics();
        password.addKeyListener(keystrokeDynamics);
        logonFieldsPanel.add(password);
        c.add(logonFieldsPanel,BorderLayout.CENTER);

        // panel for the logon button
        logonButtonPanel = new JPanel();
        logonButton = new JButton("logon");
        bHandler = new KeystrokeDynamicsButtonHandler(this);
        logonButton.addActionListener(bHandler);
        logonButtonPanel.add(logonButton);
        c.add(logonButtonPanel, BorderLayout.SOUTH);
        setSize(300,125);
        setResizable(false);
        setVisible(true);

        //Used code from http://stackoverflow.com/questions/2442599/how-to-set-jframe-to-appear-centered-regardless-of-the-monitor-resolution
        Dimension dim = Toolkit.getDefaultToolkit().getScreenSize();
        setLocation(dim.width/2-this.getSize().width/2, dim.height/2-this.getSize().height/2);
    }
}
