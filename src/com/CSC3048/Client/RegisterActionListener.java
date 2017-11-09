package com.CSC3048.Client;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.regex.Pattern;

class RegisterActionListener implements ActionListener {
    private Register register;
    private Chat_ClientThread chat_clientThread;

    public RegisterActionListener(Register register, Chat_ClientThread chat_clientThread) {
        this.register = register;
        this.chat_clientThread = chat_clientThread;
    }

    public void actionPerformed(ActionEvent e) {
        JButton button = (JButton) e.getSource();
        if (button.getText() == "Submit") {
            String name = register.getRegName().getText();
            String username = register.getRegUsername().getText();
            String pass1 = new String(register.getRegCreatePassword().getPassword());
            String pass2 = new String(register.getRegConfirmPassword().getPassword());
            if (!name.isEmpty() & !username.isEmpty() & !pass1.isEmpty() & !pass2.isEmpty() & pass1.equals(pass2)) {
                String regex ="(?!.*[;])(?=.*[A-Z]+)(?=.*[!@#$&*]+)(?=.*[0-9]+)(?=.*[a-z]+).{8,}";
                boolean valid = Pattern.matches(regex, pass1);
                if (!valid) {
                    JOptionPane.showMessageDialog(null, "Please choose a password with at least 8 characters, 1 uppercase letter and 1 special character and does not contain the character ';'", null, JOptionPane.ERROR_MESSAGE);
                    return;
                } else if (name.contains(";")) {
                    JOptionPane.showMessageDialog(null, "Please choose a name that does not contain ';'", null, JOptionPane.ERROR_MESSAGE);
                    return;
                } else if (username.contains(";")) {
                    JOptionPane.showMessageDialog(null, "Please choose a username that does not contain ';'", null, JOptionPane.ERROR_MESSAGE);
                    return;
                }
                ArrayList<Long> averageKeystrokeData = averageKeystrokeDynamics(register.getFirstKeystrokeDynamics().GetAllEvents(), register.getSecondKeystrokeDynamics().GetAllEvents());
                if(averageKeystrokeData == null) {
                    JOptionPane.showMessageDialog(null, "An error occurred. If you made a mistake while typing your password please click the clear button", null, JOptionPane.ERROR_MESSAGE);
                    return;
                }

                try {
                    Boolean result = chat_clientThread.sendRegisterDetails(username, pass1, averageKeystrokeData);
                    if (result) {
                        register.dispose();
                        JOptionPane.showMessageDialog(null, "You have registered successfully.", null, JOptionPane.INFORMATION_MESSAGE);
                        chat_clientThread.showLoginScreen();
                        return;
                    } else {
                        JOptionPane.showMessageDialog(null, "An error occurred with the registration process", null, JOptionPane.ERROR_MESSAGE);
                        return;
                    }
                } catch (ClassNotFoundException e1) {}
            } else {
                JOptionPane.showMessageDialog(null, "Ensure all form data has been entered and entered passwords match", null, JOptionPane.ERROR_MESSAGE);
                return;
            }
        }
    }

    private ArrayList<Long> averageKeystrokeDynamics(ArrayList<Long> firstKeystrokeDynamics,
                                                     ArrayList<Long> secondKeystrokeDynamics) {
        try {
            if(firstKeystrokeDynamics.size() != secondKeystrokeDynamics.size()) {
                return null;
            }

            ArrayList<Long> total = new ArrayList<>(firstKeystrokeDynamics.size());
            for (int i = 0; i < firstKeystrokeDynamics.size(); i++) {
                Long firstValue = firstKeystrokeDynamics.get(i);
                Long secondValue = secondKeystrokeDynamics.get(i);

                total.add((firstValue + secondValue) / 2);
            }
            return total;
        } catch (Exception ex) {
            return null;
        }
    }
}
