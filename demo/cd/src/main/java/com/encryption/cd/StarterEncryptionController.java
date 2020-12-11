package com.encryption.cd;


import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.bcrypt.BCrypt;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;

//MORE ON JWT PACKAGE USED HERE; https://github.com/jwtk/jjwt
//BCRYPT DOCS: https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/crypto/bcrypt/BCrypt.html

@RestController
public class StarterEncryptionController {

    //create database
    HashMap<String, User> database = new HashMap<>();

    //env import
    @Autowired
    Environment env;

    @GetMapping("/test")
    public String testGet() {
        return "Hey! The test worked!!";
    }

    @GetMapping("/all")
    public Object getAllUsers () {

        return database;
    }
    //route for signup test (bcrypt hash)
    @PostMapping("/signup")
    public User signUp( @RequestBody User user ) {
        //hash password
        String hashedPassword = BCrypt.hashpw(user.password, BCrypt.gensalt());
        user.setId();
        user.password = hashedPassword;

        //store in Db
        database.put(user.username, user);

        return user;
    }

    //route for sign-in test (bcrypt compare + jwt)
    @PutMapping("/signin")
    public String signIn( @RequestBody User user ) {

        try {
            User loggingInUser = database.get(user.username);
            String unhashedPass = user.password;
            String hashedPass = loggingInUser.password;
            boolean credentialsMatch = BCrypt.checkpw(unhashedPass, hashedPass);
            if (!credentialsMatch)
                return "login failed: credentials don't match";
            //create JWT
            Instant now = Instant.now();

            Date issuedAt = Date.from(now);
            Date expiresAt = Date.from(now.plus(40, ChronoUnit.SECONDS));

            SecretKey key = Keys.hmacShaKeyFor(env.getProperty("jwt.key").getBytes());

            String jwt = Jwts
                    .builder()
                    .setSubject("user-auth")
                    .setIssuedAt(issuedAt)
                    .setExpiration(expiresAt)
                    .claim("user", loggingInUser.id)
                    .signWith(key)
                    .compact();

            return jwt;

        } catch ( Exception e) {
            e.printStackTrace();
            return e.getMessage();
        }

    }

    @GetMapping("/testjwt")
    public String testJWT (
         @RequestBody String jwt
    ) {
        try {
            SecretKey key = Keys.hmacShaKeyFor(env.getProperty("jwt.key").getBytes());

            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(jwt);

            return "valid JWT!";
        } catch (Exception e ) {
            System.out.println(e.getMessage());
            return "invalid JWT";
        }
    }

}
