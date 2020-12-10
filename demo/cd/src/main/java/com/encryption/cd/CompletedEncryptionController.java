package com.encryption.cd;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;


//MORE ON JWT PACKAGE USED HERE; https://github.com/jwtk/jjwt
//BCRYPT DOCS: https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/crypto/bcrypt/BCrypt.html

@RestController
@RequestMapping("/completed")
public class CompletedEncryptionController {

    private final HashMap<String, User> database = new HashMap<>();

    //env import
    @Autowired
    Environment env;
    //access env

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
    public String signUp(@RequestBody User newUser) {

        newUser.setId();
        System.out.println(newUser);

        String hashedPass = BCrypt.hashpw(newUser.password, BCrypt.gensalt());

        newUser.password = hashedPass;

        database.put(newUser.username, newUser);

        return hashedPass;
    }

    //route for sign-in test (bcrypt compare + jwt)
    @PutMapping("/signin")
    public String signIn(@RequestBody User userData) {
        try {

            User loggingInUser = database.get(userData.username);

            String hashedPass = loggingInUser.password;

            //System.out.println("Hashed: " + hashedPass + "\nUSer" + userData.password );

            boolean credMatch = BCrypt.checkpw(userData.password, hashedPass  );

            if (!credMatch)
                return "login failed: credentials do not match";

            Instant now = Instant.now();

            Date signedDate = Date.from(now);
            Date expiresDate = Date.from(now.plus(1, ChronoUnit.HOURS));
            String jwtSecret = env.getProperty("jwt.key");

            System.out.println("Signed: " + signedDate.toString());
            System.out.println("Expire: " + expiresDate.toString());
            System.out.println(jwtSecret);

            String jwt = Jwts.builder()
                    .setSubject("user-auth")
                    .setIssuedAt(signedDate)
                    .setExpiration(expiresDate)
                    .claim("id", loggingInUser.id )
                    .signWith(
                        SignatureAlgorithm.HS256,
                        jwtSecret.getBytes("UTF-8")
                    )
                    .compact();

            System.out.println(jwt);

            return jwt;

        } catch (NullPointerException e) {
            return "server error: jsonwebtoken secret not defined in server";
        } catch (Exception e) {
            e.printStackTrace();
            return "login failed";
        }

    }

    @GetMapping("/testjwt")
    public String testJWT (@RequestBody String jwt) {
        try {

            String jwtSecret = env.getProperty("jwt.key");

            Jwts.parserBuilder().setSigningKey(jwtSecret.getBytes("UTF-8")).build().parseClaimsJws(jwt);

            return "valid JWT!";

        } catch (Exception e) {
            System.out.println(e.getMessage());
            return "invalid JWT";
        }

    }

}
