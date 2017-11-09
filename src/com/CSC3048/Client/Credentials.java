package com.CSC3048.Client;

public class Credentials implements java.io.Serializable {

    private String username;
    private String password;
    private String keystrokeData;
    private String registerMessage;

    public Credentials(String username, String password, String keystrokeData, String registerMessage) {
        this.username = username;
        this.password = password;
        this.keystrokeData = keystrokeData;
        this.registerMessage = registerMessage;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getKeystrokeData() {
        return keystrokeData;
    }

    public String getRegisterMessage() {
        return registerMessage;
    }

    @Override
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(username);
        stringBuilder.append(password);
        stringBuilder.append(password);
        stringBuilder.append(registerMessage);
        return stringBuilder.toString();
    }
}
