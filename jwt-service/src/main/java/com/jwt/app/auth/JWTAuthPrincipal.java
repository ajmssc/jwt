package com.jwt.app.auth;

import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenClaim;
import com.jwt.app.models.User;
import io.dropwizard.auth.PrincipalImpl;

import java.util.Arrays;
import java.util.HashMap;

/**
 * Created by ajmssc on 8/16/15.
 */
public class JWTAuthPrincipal extends PrincipalImpl {
    private final JsonWebTokenClaim claim;

    public JWTAuthPrincipal(JsonWebTokenClaim claim) {
        super((String) claim.getParameter("id"));
        this.claim = claim;
    }

    public Object get(String field) {
        return claim.getParameter(field);
    }

    public HashMap<String, String> toMap() {
        HashMap<String, String> result = new HashMap();
        Arrays.asList(User.class.getFields())
                .stream()
                .filter(f -> f.isAnnotationPresent(JWTUserManager.JWTField.class))
                .forEach(f -> result.put(f.getName(), (String) claim.getParameter(f.getName())));
        return result;
    }
}
