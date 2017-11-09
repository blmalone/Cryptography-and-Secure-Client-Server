package com.CSC3048.Client;

import com.CSC3048.EncryptionAlgorithms.AES.AESEncryption;
import com.CSC3048.EncryptionAlgorithms.SDES.SDESEncryption;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

class RadioButtonActionListener implements ActionListener {
    private final  String[][] aesKey = new String[][]{
            {"2b","28","ab","09"},
            {"7e","ae","f7","cf"},
            {"15","d2","15","4f"},
            {"16","a6","88","3c"}
    };
    private Client client;

    public RadioButtonActionListener(Client client) {
        this.client = client;
    }

    @Override
    public void actionPerformed(ActionEvent event) {
        JRadioButton button = (JRadioButton) event.getSource();
        if (button.getText() == "AES") {
            client.setSymmetricEncryption(new AESEncryption());

        } else {
            client.setSymmetricEncryption(new SDESEncryption());
        }
    }
}