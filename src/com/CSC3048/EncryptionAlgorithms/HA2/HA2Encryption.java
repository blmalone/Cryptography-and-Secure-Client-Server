package com.CSC3048.EncryptionAlgorithms.HA2;

public class HA2Encryption {

    public static String hashCode(String plainText) {
        String results = "";
        int IV = 76;
        int distanceFromUnicodeCharSet = 22;
        results += String.valueOf(IV / 10) + String.valueOf(IV % 10);

        for (int i = 0; i < plainText.length(); i++) {
            if (plainText.charAt(i) == ' ') continue;
            results += " ";
            char ch = plainText.charAt(i);
            int val = 0;
            if (ch >= 'A' && ch <= 'Z') {
                ch = (char) (ch - 'A' + 'a');
                val = ch - 'a';
            } else if (ch >= '0' && ch <= '9') {
                val = (char) (ch - distanceFromUnicodeCharSet);
            }
            int prv = IV;
            IV = (IV + val) % 100;
            IV = (IV * 7) % 100;
            int rev = (IV % 10) * 10 + (IV / 10);
            IV = (rev + prv) % 100;
            results += String.valueOf(IV / 10) + String.valueOf(IV % 10);
        }
        return results;
    }
}
