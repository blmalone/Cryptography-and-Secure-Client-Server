package com.CSC3048.Server;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

public class DiskCredentials implements ICredentialManager {
    private static final String filename = "logins.txt";
    private static final long threshold = 1000000000;
    @Override
    public boolean addCredentials(String username, String password, String keystrokeData) {
        try {
            FileWriter fileWriter = new FileWriter(filename, true);
            BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
            bufferedWriter.write(username + ";" + password + ";" + keystrokeData);
            bufferedWriter.newLine();
            bufferedWriter.close();
            return true;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    @Override
    public boolean validCredentials(String userName, String password, String keystrokeData) {
        try {
            FileReader fileReader = new FileReader(filename);
            BufferedReader bufferedReader = new BufferedReader(fileReader);
            String line;
            while((line = bufferedReader.readLine()) != null) {
                if(line.startsWith(userName)) {
                    String[] lineSegments = line.split(";");
                    boolean passwordsMatch = lineSegments[1].equals(password);

                    if(!passwordsMatch) {
                        return false;
                    }

                    boolean keystrokesMatch = true;
                    String savedKeystrokeData = lineSegments[2];
                    String[] keystrokes = savedKeystrokeData.split(",");
                    String[] inputtedKeyStrokes = keystrokeData.split(",");

                    for (int i = 0; i < inputtedKeyStrokes.length; i++) {
                        String localKeystroke = keystrokes[i];
                        localKeystroke = localKeystroke.trim();
                        Long savedKeystroke = Long.parseLong(localKeystroke);
                        String inputtedKeyStroke = inputtedKeyStrokes[i];
                        inputtedKeyStroke = inputtedKeyStroke.trim();
                        Long providedKeystroke = Long.parseLong(inputtedKeyStroke);
                        //Take the larger of the two keystrokes and subtract the smaller and make sure that the value
                        //less than the threshold
                        long resultToEvaluate = 0;
                        if(savedKeystroke > providedKeystroke) {
                            resultToEvaluate = savedKeystroke - providedKeystroke;
                        } else {
                            resultToEvaluate = providedKeystroke - savedKeystroke;
                        }
                        if(resultToEvaluate > threshold) {
                            keystrokesMatch = false;
                            break;
                        }
                    }
                    return passwordsMatch && keystrokesMatch;
                }
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return false;
    }
}
