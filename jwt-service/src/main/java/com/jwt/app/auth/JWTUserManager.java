package com.jwt.app.auth;


import com.jwt.app.models.User;
import org.bson.types.ObjectId;
import org.mongodb.morphia.Key;
import org.mongodb.morphia.dao.BasicDAO;
import org.mongodb.morphia.query.Query;
import org.mongodb.morphia.query.UpdateResults;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Field;

/**
 * Created by ajmssc on 8/19/15.
 */
public class JWTUserManager {
    private final BasicDAO<User, ObjectId> dao;

    public JWTUserManager(BasicDAOFactory factory) {
        dao = factory.getDAO(User.class);

    }

    public User getUser(String email) {
        return dao.findOne("email", email);
    }

    public Key<User> createUser(User newUser) {
        String email = newUser.email;
        User existingUser = getUser(email);
        if (existingUser != null) {
            throw new AuthenticationException("Cannot register new user, user already exists");
        }
        try {
            return dao.save(newUser);
        } catch (Exception e) {
            throw new AuthenticationException("Error creating user object");
        }
    }

    public User sanitizeUser(User user) {
        if (user == null) return null;
        for (Field field : User.class.getDeclaredFields()) {
            try {
                if (field.isAnnotationPresent(Sensitive.class) && field.get(user) != null) {
                    field.set(user, null);
                }
            } catch (IllegalAccessException ignore) {
            }
        }
        return user;
    }

    public User getUserByIdSanitized(String id) {
        return sanitizeUser(dao.get(new ObjectId(id)));
    }

    public Boolean updateField(String id, String field, Object value) {
        try {
            Field classField = User.class.getField(field);
            if (!classField.isAnnotationPresent(ReadOnly.class)) {
                Query<User> userQuery = dao.createQuery().field("_id").equal(new ObjectId(id));
                UpdateResults updateQuery = dao.update(userQuery, dao.createUpdateOperations().set(field, value));
                return updateQuery.getUpdatedCount() == 1;
            }
            return false;
        } catch (NoSuchFieldException e) {
            return false;
        }
    }

    /**
     * Field should not be transmitted externally
     */
    @Target(ElementType.FIELD)
    @Retention(RetentionPolicy.RUNTIME)
    public @interface Sensitive {
    }

    /**
     * Field cannot be updated
     */
    @Target(ElementType.FIELD)
    @Retention(RetentionPolicy.RUNTIME)
    public @interface ReadOnly {
    }

    /**
     * Annotation that marks a field to be included in the JWT token
     */
    @Target(ElementType.FIELD)
    @Retention(RetentionPolicy.RUNTIME)
    public @interface JWTField {
    }
}
