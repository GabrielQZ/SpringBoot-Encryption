package com.encryption.cd;


import io.jsonwebtoken.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.bcrypt.BCrypt;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;

//MORE ON JWT PACKAGE USED HERE; https://github.com/jwtk/jjwt
//BCRYPT DOCS: https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/crypto/bcrypt/BCrypt.html

@RestController
public class StarterEncryptionController {

    //create database

    //env import

    @GetMapping("/test")
    public String testGet() {
        return "Hey! The test worked!!";
    }

    @GetMapping("/all")
    public Object getAllUsers () {

        return "temp";// return database
    }
    //route for signup test (bcrypt hash)
    @PostMapping("/signup")
    public String signUp(
            //grab userdata from body
    ) {


        return "temp";
    }

    //route for sign-in test (bcrypt compare + jwt)
    @PutMapping("/signin")
    public String signIn(
            //grab userdata from body
    ) {


        return "temp";

    }

    @GetMapping("/testjwt")
    public String testJWT (
            //grab jwt from body
    ) {


        return "temp";
    }

}
