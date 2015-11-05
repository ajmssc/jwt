package com.jwt.app.auth;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.HashMap;

/**
 * Created by ajmssc on 10/22/15.
 * Description:
 */
public class AuthenticationException extends WebApplicationException {

    public AuthenticationException(String message) {
        super(Response.status(Response.Status.BAD_REQUEST)
                .entity(buildMessage(message))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build());
    }

    public AuthenticationException(Response.Status status, String message) {
        super(Response.status(status)
                .entity(buildMessage(message))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build());
    }

    private static HashMap<String, String> buildMessage(String errorMessage) {
        return new HashMap<String, String>() {{
            put("error", errorMessage);
        }};
    }
}