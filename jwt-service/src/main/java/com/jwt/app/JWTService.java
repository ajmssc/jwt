package com.jwt.app;

import com.github.toastshaman.dropwizard.auth.jwt.JWTAuthFilter;
import com.github.toastshaman.dropwizard.auth.jwt.JsonWebTokenParser;
import com.github.toastshaman.dropwizard.auth.jwt.hmac.HmacSHA512Verifier;
import com.github.toastshaman.dropwizard.auth.jwt.parser.DefaultJsonWebTokenParser;
import com.jwt.app.auth.AuthResource;
import com.jwt.app.auth.JWTAuthenticator;
import io.dropwizard.assets.AssetsBundle;
import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;

import io.dropwizard.setup.Environment;
import org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Principal;


public class JWTService extends Application<JWTConfiguration> {
    private static final Logger LOG = LoggerFactory.getLogger(JWTService.class);


    public static void main(String[] args) throws Exception {
        new JWTService().run(args);
    }


    @Override
    public void initialize(Bootstrap<JWTConfiguration> bootstrap) {
        bootstrap.addBundle(new AssetsBundle("/app/", "/"));

//        guiceBundle = GuiceBundle.<JWTConfiguration>newBuilder()
//                .addModule(new AbstractModule() {
//                    @Override
//                    protected void configure() {
//                        bind(Test.class);
//                    }
//
//                    @Provides
//                    public MongoManaged mongoManaged(JWTConfiguration configuration) throws Exception {
//                        return new MongoManaged(configuration.mongo);
//                    }
//                })
//                .setConfigClass(JWTConfiguration.class)
////                .enableAutoConfig(getClass().getPackage().getName())
//                .build();
//
//        bootstrap.addBundle(guiceBundle);

        //bootstrap.addBundle(hibernate);
        //ObjectMapper mapper = bootstrap.getObjectMapper();
        //mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    @Override
    public void run(JWTConfiguration configuration, Environment environment) throws Exception {

        MongoManaged mongo = new MongoManaged(configuration.mongo);

        // Resources
        JWTBasicDAOFactory daoFactory = new JWTBasicDAOFactory(mongo);

        // Auth Endpoint
        JWTAuthenticator authenticator = new JWTAuthenticator(daoFactory, configuration.getJwtTokenSecret(), configuration.getJwtSessionDuration());
        environment.jersey().register(new AuthResource(authenticator));


        //JWT Authentication
        final JsonWebTokenParser tokenParser = new DefaultJsonWebTokenParser();
        final HmacSHA512Verifier tokenVerifier = new HmacSHA512Verifier(configuration.getJwtTokenSecret());
        environment.jersey().register(new AuthDynamicFeature(
                new JWTAuthFilter.Builder<>()
                        .setTokenParser(tokenParser)
                        .setTokenVerifier(tokenVerifier)
                        .setRealm("realm")
                        .setPrefix("Bearer")
                        .setAuthenticator(authenticator)
                        .buildAuthFilter()));
        environment.jersey().register(new AuthValueFactoryProvider.Binder<>(Principal.class));
        environment.jersey().register(RolesAllowedDynamicFeature.class);
    }

}
