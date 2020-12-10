package com.encryption.cd;

import java.util.HashSet;
import java.util.Set;

public class User {


    private static final int ID_CHAR_LIMIT = 1_000_000_000;
    private static final int ID_LENGTH = 10;

    private static final Set<String> allUserIds = new HashSet<>();

    public String id;
    public String username;
    public String password;

    @Override
    public String toString(){
        return "\nId: " + id + "\nUsername: " + username + "\nPassword: " + password + "\n";
    }

    public void setId() {
        id = genId();
    }


    private static String genId () {
        //Ensure there are no repeats by comparing to list of all account numbers
        String randomNumber = formatId(Integer.toString((int) Math.round(Math.random() * ID_CHAR_LIMIT)));
        while (allUserIds.contains(randomNumber)) {
            randomNumber = formatId(Integer.toString((int) Math.round(Math.random() * ID_CHAR_LIMIT)));
        }
        allUserIds.add(randomNumber);
        return randomNumber;
    }

    public static String formatId ( String accountNumber ) {
        int missingZeros = ID_LENGTH - accountNumber.length();
        String zeros = new String(new char[missingZeros]).replace("\0", "0");;
        return zeros + accountNumber;
    }

}
