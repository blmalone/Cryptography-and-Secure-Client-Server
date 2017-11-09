package com.CSC3048.Server;

public interface ICredentialManager {
    boolean addCredentials(String username, String password, String keystrokeData);
    boolean validCredentials(String userName, String password, String keystrokeData);
}
