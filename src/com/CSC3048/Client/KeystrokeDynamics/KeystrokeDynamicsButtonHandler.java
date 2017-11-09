package com.CSC3048.Client.KeystrokeDynamics;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;

public class KeystrokeDynamicsButtonHandler implements ActionListener {
    KeystrokeDynamics keystrokeDynamics;

    public KeystrokeDynamicsButtonHandler(KeystrokeDynamicsGUI keystrokeDynamicsGUI) {
        keystrokeDynamics = keystrokeDynamicsGUI.keystrokeDynamics;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        ArrayList<Long> allEvents = keystrokeDynamics.GetAllEvents();

        System.out.println("Validating Login");

        for(Long event : allEvents) {
            System.out.println(event);
        }
    }
}
