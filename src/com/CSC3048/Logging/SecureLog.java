package com.CSC3048.Logging;


import com.CSC3048.EncryptionAlgorithms.HA2.HA2Encryption;
import com.CSC3048.EncryptionAlgorithms.AES.AESEncryption;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class SecureLog{
    String fileHash;
    String filePath;

    // Key used to encrypt each line of the log file
    String[][] key = new String[][]{
            {"2f","28","fb","a9"},
            {"8b","6e","c7","bf"},
            {"1c","52","55","5f"},
            {"15","36","78","2c"}
    };

    public SecureLog(){
        this.filePath = "SecureLog.log";
    }

    /**
     * Checks the integrity of the file before writing the param 'str' to the log file with a timestamp (encrypted using AES)
     * @param str - Event to be logged
     * @return - true if write was successful and false if it failed due to file integrity
     */
    public boolean write(String str){
        DateTimeFormatter dtFormat = DateTimeFormatter.ofPattern("yyy-MM-dd HH:mm:ss");
        LocalDateTime dateTime = LocalDateTime.now();
        String timeStamp = dtFormat.format(dateTime);

        //check if hash matches in-memory hash
        ensureFileExists();

        if(ensureFileIntegrity()){
            try(FileWriter fileWriter = new FileWriter(this.filePath, true);
                BufferedWriter bufferedWriter = new BufferedWriter(fileWriter)){
                AESEncryption aes = new AESEncryption(key);
                String encrypted = aes.encrypt(timeStamp+": "+str);
                bufferedWriter.write(encrypted);
                bufferedWriter.newLine();

            }catch(IOException e){
                e.printStackTrace();
            }
            updateHash();
            return true;

        }else{
            return false;
        }
    }

    /**
     * Updates the last known hash
     */
    private void updateHash()  {
        try {
            String contents = readFileToString(this.filePath);
            this.fileHash = HA2Encryption.hashCode(contents);
        }catch(IOException e){
            e.printStackTrace();
        }
    }

    /**
     * Checks if the SecureLog file exists and if it doesn't it gets created.
     */
    private void ensureFileExists() {
        try {
            File file = new File(this.filePath);
            file.createNewFile();
        }catch(IOException e){
            e.printStackTrace();
        }
    }

    /**
     * Reads the contents of a file to a string
     * @param path - Path to file
     * @return - String representation of the contents of the file
     * @throws IOException
     */
    private String readFileToString(String path) throws IOException
    {
        byte[] bytes = Files.readAllBytes(Paths.get(path));
        return new String(bytes);
    }

    /**
     * Check the integrity of the file
     * @return - true if the the file has not been tampered with, false if file has been tampered with
     */
    private boolean ensureFileIntegrity(){
        //read contents of file to string
        String contents="";
        try {
            contents = readFileToString(this.filePath);
        } catch (IOException e) {

            e.printStackTrace();
        }
        String hash = HA2Encryption.hashCode(contents);
        if(this.fileHash != null){
            if(hash.equals(fileHash)){
                return true;
            }else{
                return false;
            }
        }
        return true;
    }

    /**
    Read log file and decrypt
     */
    private String read(){
        StringBuilder log = new StringBuilder();
        try(FileReader reader = new FileReader(this.filePath);
            BufferedReader bufferedReader = new BufferedReader(reader)){
            AESEncryption aes = new AESEncryption(key);
            String line;

            while((line = bufferedReader.readLine()) != null){
                log.append(aes.decrypt(line));
            }

        }catch(IOException e){
            e.printStackTrace();
        }
        return log.toString();
    }
}
