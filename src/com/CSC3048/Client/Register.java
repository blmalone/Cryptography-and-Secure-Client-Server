package com.CSC3048.Client;

import com.CSC3048.Client.KeystrokeDynamics.KeystrokeDynamics;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

public class Register extends JFrame {

	private JTextField regName;
	private JTextField regUsername;
	private JPasswordField regCreatePassword;
	private JPasswordField regConfirmPassword;
	private KeystrokeDynamics firstKeystrokeDynamics, secondKeystrokeDynamics;
	private Chat_ClientThread chat_clientThread;
	private Client client;
	/**
	 * Create the frame.
	 */
	public Register(Client client, Chat_ClientThread chat_clientThread) {
		this.client = client;
		this.chat_clientThread = chat_clientThread;

		setTitle("Client - Register");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 450, 300);
		JPanel regPassword = new JPanel();
		regPassword.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(regPassword);
		GridBagLayout gbl_regPassword = new GridBagLayout();
		gbl_regPassword.columnWidths = new int[]{0, 0, 0, 0, 0};
		gbl_regPassword.rowHeights = new int[]{0, 0, 0, 0, 0, 0, 0, 0};
		gbl_regPassword.columnWeights = new double[]{0.0, 0.0, 0.0, 1.0, Double.MIN_VALUE};
		gbl_regPassword.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, Double.MIN_VALUE};
		regPassword.setLayout(gbl_regPassword);
		
		JLabel lblRegName = new JLabel("Name:");
		GridBagConstraints gbc_lblRegName = new GridBagConstraints();
		gbc_lblRegName.insets = new Insets(0, 0, 5, 5);
		gbc_lblRegName.gridx = 1;
		gbc_lblRegName.gridy = 1;
		regPassword.add(lblRegName, gbc_lblRegName);
		
		regName = new JTextField();
		GridBagConstraints gbc_regName = new GridBagConstraints();
		gbc_regName.insets = new Insets(0, 0, 5, 0);
		gbc_regName.fill = GridBagConstraints.HORIZONTAL;
		gbc_regName.gridx = 3;
		gbc_regName.gridy = 1;
		regPassword.add(regName, gbc_regName);
		regName.setColumns(10);
		
		JLabel lblRegUsername = new JLabel("Username:");
		GridBagConstraints gbc_lblRegUsername = new GridBagConstraints();
		gbc_lblRegUsername.insets = new Insets(0, 0, 5, 5);
		gbc_lblRegUsername.gridx = 1;
		gbc_lblRegUsername.gridy = 2;
		regPassword.add(lblRegUsername, gbc_lblRegUsername);
		
		regUsername = new JTextField();
		GridBagConstraints gbc_regUsername = new GridBagConstraints();
		gbc_regUsername.insets = new Insets(0, 0, 5, 0);
		gbc_regUsername.fill = GridBagConstraints.HORIZONTAL;
		gbc_regUsername.gridx = 3;
		gbc_regUsername.gridy = 2;
		regPassword.add(regUsername, gbc_regUsername);
		regUsername.setColumns(10);

		JLabel lblCreatePassword = new JLabel("Create Password:");
		GridBagConstraints gbc_lblCreatePassword = new GridBagConstraints();
		gbc_lblCreatePassword.insets = new Insets(0, 0, 5, 5);
		gbc_lblCreatePassword.gridx = 1;
		gbc_lblCreatePassword.gridy = 3;
		regPassword.add(lblCreatePassword, gbc_lblCreatePassword);
		
		regCreatePassword = new JPasswordField();
		GridBagConstraints gbc_regCreatePassword = new GridBagConstraints();
		gbc_regCreatePassword.insets = new Insets(0, 0, 5, 0);
		gbc_regCreatePassword.fill = GridBagConstraints.HORIZONTAL;
		gbc_regCreatePassword.gridx = 3;
		gbc_regCreatePassword.gridy = 3;
		regPassword.add(regCreatePassword, gbc_regCreatePassword);

		firstKeystrokeDynamics = new KeystrokeDynamics();
		regCreatePassword.addKeyListener(firstKeystrokeDynamics);

		JLabel lblConfirmPassword = new JLabel("Confirm Password:");
		GridBagConstraints gbc_lblConfirmPassword = new GridBagConstraints();
		gbc_lblConfirmPassword.insets = new Insets(0, 0, 5, 5);
		gbc_lblConfirmPassword.gridx = 1;
		gbc_lblConfirmPassword.gridy = 4;
		regPassword.add(lblConfirmPassword, gbc_lblConfirmPassword);
		
		regConfirmPassword = new JPasswordField();
		GridBagConstraints gbc_regConfirmPassword = new GridBagConstraints();
		gbc_regConfirmPassword.insets = new Insets(0, 0, 5, 0);
		gbc_regConfirmPassword.fill = GridBagConstraints.HORIZONTAL;
		gbc_regConfirmPassword.gridx = 3;
		gbc_regConfirmPassword.gridy = 4;
		regPassword.add(regConfirmPassword, gbc_regConfirmPassword);

		secondKeystrokeDynamics = new KeystrokeDynamics();
		regConfirmPassword.addKeyListener(secondKeystrokeDynamics);

		JLayeredPane layeredPane = new JLayeredPane();
		GridBagConstraints gbc_layeredPane = new GridBagConstraints();
		gbc_layeredPane.fill = GridBagConstraints.BOTH;
		gbc_layeredPane.gridx = 3;
		gbc_layeredPane.gridy = 6;
		regPassword.add(layeredPane, gbc_layeredPane);

		JButton btnSubmit = new JButton("Submit");
		RegisterActionListener registerActionListener = new RegisterActionListener(this, chat_clientThread);
		btnSubmit.addActionListener(registerActionListener);

		btnSubmit.setBounds(10, 11, 89, 23);
		layeredPane.add(btnSubmit);

		JButton btnClear = new JButton("Clear");
		btnClear.addActionListener(e -> {
            regName.setText("");
            regUsername.setText("");
            regCreatePassword.setText("");
            regConfirmPassword.setText("");
			firstKeystrokeDynamics.reset();
			secondKeystrokeDynamics.reset();
        });
		btnClear.setBounds(106, 11, 89, 23);
		layeredPane.add(btnClear);
	}

	public JTextField getRegName() {
		return regName;
	}

	public JTextField getRegUsername() {
		return regUsername;
	}

	public JPasswordField getRegCreatePassword() {
		return regCreatePassword;
	}

	public JPasswordField getRegConfirmPassword() {
		return regConfirmPassword;
	}

	public KeystrokeDynamics getFirstKeystrokeDynamics() {
		return firstKeystrokeDynamics;
	}

	public KeystrokeDynamics getSecondKeystrokeDynamics() {
		return secondKeystrokeDynamics;
	}
}
