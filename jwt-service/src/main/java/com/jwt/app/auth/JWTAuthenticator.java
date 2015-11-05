package com.jwt.app.auth;

import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.google.common.base.Optional;
import com.jwt.app.models.User;
import io.dropwizard.auth.Authenticator;
import org.apache.commons.validator.EmailValidator;
import org.apache.log4j.Logger;
import org.mindrot.jbcrypt.BCrypt;
import org.mongodb.morphia.Key;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.core.Context;
import java.lang.reflect.Field;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by ajmssc on 8/16/15.
 */
public class JWTAuthenticator implements Authenticator<JsonWebToken, Principal> {
    private final JWTUserManager userManager;
    private final JWTManager jwtManager;
    private final Logger log = Logger.getLogger(this.getClass());

    private final String JWT_AUTH_TOKEN_HEADER = "JWT_AUTH_TOKEN";
    @Context
    private HttpServletResponse anotherServletResponse;


    public JWTAuthenticator(BasicDAOFactory factory, byte[] jwtTokenSecret, int jwtSessionDuration) {
        this.jwtManager = new JWTManager(jwtTokenSecret, jwtSessionDuration);
        this.userManager = new JWTUserManager(factory);
    }

    public User buildNewUser(Map<String, String> formData) {
        if (formData == null) throw new AuthenticationException("No data provided");
        String password = formData.get("password");
        String confirmPassword = formData.get("confirmPassword");
        String email = formData.get("email");

        if (!emailMeetsRequirements(email) || !passwordMeetsRequirements(password, confirmPassword))
            throw new AuthenticationException("Error with email or password");

        User newUser = new User();
        for (Field field : User.class.getDeclaredFields()) {
            String fieldName = field.getName();
            if (!field.isAnnotationPresent(JWTUserManager.Sensitive.class)
                    && field.isAnnotationPresent(org.mongodb.morphia.annotations.Id.class)
                    && formData.containsKey(fieldName)) {
                try {
                    field.set(newUser, formData.get(fieldName));
                } catch (IllegalAccessException e) {
                    log.error("Creating new user, tried to set protected field " + fieldName + " to value " + formData.get(fieldName));
                }
            }
        }
        newUser.encryptedPassword = BCrypt.hashpw(password, BCrypt.gensalt());
        return newUser;
    }

    private boolean emailMeetsRequirements(String email) {
        //TODO: finish
        if (!EmailValidator.getInstance().isValid(email)) {
            throw new AuthenticationException("Email is invalid");
        }
        return true;
    }

    private boolean passwordMeetsRequirements(String password, String confirmPassword) {
        if (password == null || password.isEmpty()) throw new AuthenticationException("Password is blank");
        if (!password.equals(confirmPassword)) throw new AuthenticationException("Passwords provided didn't match");
        if (password.length() < 6) throw new AuthenticationException("Password is too short");
        //TODO: finish
        return true;
    }

    private Boolean verifyPassword(String plainTextPassword, String encryptedPassword) {
        return BCrypt.checkpw(plainTextPassword, encryptedPassword);
    }

    public User authenticate(String email, String password, HttpServletResponse request) {
        try {
            User authUser = userManager.getUser(email);
            if (authUser != null && verifyPassword(password, authUser.encryptedPassword)) {
                authUser.encryptedPassword = "";
                injectJWTInHeader(request, authUser);
                return authUser;
            }
        } catch (Exception e) {
            throw new NotAuthorizedException(e);
        }
        throw new NotAuthorizedException("Not authorized");
    }

    public User register(User newUser, HttpServletResponse response) {
        Key<User> userKey = userManager.createUser(newUser);
        if (userKey == null) throw new AuthenticationException("Failed to create new user");
        newUser.encryptedPassword = "";
        injectJWTInHeader(response, newUser);
        return newUser;
    }


    // Return principal based on JWT
    @Override
    public Optional<Principal> authenticate(JsonWebToken token) {
        return jwtManager.getTokenData(token);
    }


    public void requestTokenRefresh(JWTAuthPrincipal p, HttpServletResponse response) {
        User authUser = userManager.getUserByIdSanitized((String) p.get("id"));
        if (authUser == null) {
            throw new NotAuthorizedException("User was deleted");
        }
        injectJWTInHeader(response, authUser);
    }


    public void injectJWTInHeader(HttpServletResponse response, User authUser) {
        Map<String, Object> jwtMap = new HashMap<>();
        for (Field field : User.class.getDeclaredFields()) {
            try {
                String fieldName = field.getName();
                if (field.isAnnotationPresent(JWTUserManager.JWTField.class)
                        && !field.isAnnotationPresent(JWTUserManager.Sensitive.class)
                        && field.get(authUser) != null) {
                    jwtMap.put(fieldName, field.get(authUser));
                }
            } catch (IllegalAccessException ignore) {
            }
        }
        response.setHeader(JWT_AUTH_TOKEN_HEADER, jwtManager.getToken(jwtMap));
    }


}