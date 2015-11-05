package com.jwt.app.auth;

import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenValidator;
import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Signer;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebToken;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenClaim;
import com.github.toastshaman.dropwizard.auth.jwt.model.JsonWebTokenHeader;
import com.google.common.base.Optional;
import org.joda.time.Duration;
import org.joda.time.Instant;

import java.security.Principal;
import java.util.Map;

/**
 * Created by ajmssc on 8/18/15.
 */
public class JWTManager {
    private static final String JWT_SUBJECT = "jwt-token";
    private final byte[] tokenSecret;
    private final int sessionDuration;

    public JWTManager(byte[] seed, int sessionDuration) {
        this.tokenSecret = seed;
        this.sessionDuration = sessionDuration;
    }

    public String getToken(Map<String, Object> userData) {
        final HmacSHA512Signer signer = new HmacSHA512Signer(tokenSecret);
        JsonWebTokenClaim.Builder jsonClaimBuilder = JsonWebTokenClaim.builder()
                .subject(JWT_SUBJECT)
                .issuedAt(new Instant().toDateTime())
                .expiration(new Instant().plus(Duration.standardSeconds(sessionDuration)).toDateTime());
        for (String key : userData.keySet()) {
            jsonClaimBuilder.param(key, userData.get(key));
        }

        final JsonWebToken token = JsonWebToken.builder()
                .header(JsonWebTokenHeader.HS512())
                .claim(jsonClaimBuilder.build())
                .build();
        return signer.sign(token);
    }

    public Optional<Principal> getTokenData(JsonWebToken token) {
        final JsonWebTokenValidator expiryValidator = new JWTExpirationValidator();
        // All JsonWebTokenExceptions will result in a 401 Unauthorized response.
        expiryValidator.validate(token);

        if (JWT_SUBJECT.equals(token.claim().subject())) {
            final Principal principal = new JWTAuthPrincipal(token.claim());
            return Optional.of(principal);
        }

        return Optional.absent();
    }




}
