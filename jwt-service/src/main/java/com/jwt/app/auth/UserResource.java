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
 * Created by ajmssc on 10/27/15.
 * Description:
 */
@Path("/user")
@Produces(MediaType.APPLICATION_JSON)
public class UserResource {

    @Context
    private HttpServletResponse response;
    @Context
    private Request request;

    private JWTUserManager userManager;

    public UserResource(BasicDAOFactory factory) {
        this.userManager = new JWTUserManager(factory);
    }


    @GET
    @Path("/profile")
    public User getProfile(@Auth Principal user) {
        JWTAuthPrincipal p = (JWTAuthPrincipal) user;
        return userManager.getUserByIdSanitized((String) p.get("id"));
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("/field")
    public Boolean updateField(@Auth Principal user, Map<String, String> formData) {
        if (formData == null
                || !formData.containsKey("field")
                || !formData.containsKey("value")) throw new NotAcceptableException("Missing data");
        String field = formData.get("field");
        Object value = formData.get("value");
        JWTAuthPrincipal p = (JWTAuthPrincipal) user;
        return userManager.updateField((String) p.get("id"), field, value);
    }

}
