package com.CSC3048.Client;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

class LoginActionListener implements ActionListener {
    private Client client;
    private Chat_ClientThread chat_clientThread;

    public LoginActionListener(Client client, Chat_ClientThread chat_clientThread) {
        this.client = client;
        this.chat_clientThread = chat_clientThread;
    }

    public void actionPerformed(ActionEvent e) {
        if (e.getSource() == client.logonButton) {
            try {
                chat_clientThread.sendLoginDetails();
            } catch (ClassNotFoundException e1) {}
        }
    }
}
