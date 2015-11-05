package com.jwt.app.auth;

import com.jwt.app.models.User;
import io.dropwizard.auth.Auth;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Request;
import java.security.Principal;
import java.util.Map;

/**
 * Created by ajmssc on 8/16/15.
 */
@Path("/auth")
@Produces(MediaType.APPLICATION_JSON)
public class AuthResource {

    private final JWTAuthenticator authenticator;
    @Context
    private HttpServletResponse response;
    @Context
    private Request request;

    public AuthResource(JWTAuthenticator authenticator) {
        this.authenticator = authenticator;
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("/login")
    public User login(Map<String, String> formData) {
        if (formData == null
                || !formData.containsKey("email")
                || !formData.containsKey("password")) throw new NotAcceptableException("Missing email or password");
        String email = formData.get("email");
        String password = formData.get("password");
        return authenticator.authenticate(email, password, response);
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("/register")
    public User register(Map<String, String> formData) {
        User newUser = authenticator.buildNewUser(formData);
        return authenticator.register(newUser, response);
    }

    @GET
    @Path("/check-token")
    public Map<String, String> checkToken(@Auth Principal user) {
        JWTAuthPrincipal p = (JWTAuthPrincipal) user;
        return p.toMap();
    }

    @GET
    @Path("/refreshToken")
    public Map<String, String> refreshToken(@Auth Principal user) {
        JWTAuthPrincipal p = (JWTAuthPrincipal) user;
        authenticator.requestTokenRefresh(p, response);
        return p.toMap();
    }

    /**
     * Fake endpoint. Does nothing because logout is basically the client deleting their JWT
     */
    @GET
    @Path("/logout")
    public Map<String, String> logout(@Auth Principal user) {
        return null;
    }
}