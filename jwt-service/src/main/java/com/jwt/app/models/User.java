package com.jwt.app.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.jwt.app.auth.JWTUserManager;
import org.mongodb.morphia.annotations.Entity;
import org.mongodb.morphia.annotations.Id;

import java.util.Date;

/**
 * Created by ajmssc on 8/19/15.
 */
@Entity
public class User {

    @Id
    @JWTUserManager.JWTField
    @JWTUserManager.ReadOnly
    public String id;

    @JWTUserManager.JWTField
    public String displayName;

    @JWTUserManager.JWTField
    @JWTUserManager.ReadOnly
    public String email;


    @JWTUserManager.Sensitive
    @JWTUserManager.ReadOnly
    @JsonIgnore
    public String encryptedPassword;

    @JWTUserManager.JWTField
    public String firstName;

    @JWTUserManager.JWTField
    public String lastName;

    public Date birthdate;

    public String bio;
}
