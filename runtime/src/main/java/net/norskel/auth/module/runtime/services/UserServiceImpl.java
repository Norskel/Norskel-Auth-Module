package net.norskel.auth.module.runtime.services;

import io.quarkus.arc.DefaultBean;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.NotFoundException;
import net.norskel.auth.module.runtime.config.AuthBuildTimeConfig;
import net.norskel.auth.module.runtime.config.AuthRuntimeConfig;
import net.norskel.auth.module.runtime.entities.UserEntity;
import net.norskel.auth.module.runtime.enums.UserStateEnum;
import net.norskel.auth.module.runtime.spi.UserService;
import net.norskel.auth.module.runtime.spi.UserStore;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.UUID;

/**
 * UserServiceImpl
 *
 * @author Norskel
 * @since 17.04.2026
 **/
@DefaultBean
@ApplicationScoped
public class UserServiceImpl implements UserService {

    @Inject
    UserStore userStore;

    @Inject
    AuthRuntimeConfig config;

    @Override
    public List<UserEntity> findAll() {
        return userStore.findAll();
    }

    @Override
    public UserEntity upsertFromOidc(String subject, Object email, Object name) {
        Objects.requireNonNull(subject);
        String emailStr = email != null ? email.toString() : null;
        String nameStr = name != null ? name.toString() : null;

        return userStore.findByOidcId(subject)
                .map(existing -> syncIfChanged(existing, emailStr, nameStr))
                .orElseGet(() -> createFromOidc(subject, emailStr, nameStr));
    }

    private UserEntity syncIfChanged(UserEntity user, String email, String name) {
        boolean changed = false;
        if (email != null && !email.equals(user.getEmail())) {
            user.setEmail(email); changed = true;
        }
        if (name != null && !name.equals(user.getUsername())) {
            user.setUsername(name); changed = true;
        }
        return changed ? userStore.update(user) : user;
    }

    private UserEntity createFromOidc(String subject, String email, String name) {
        UserEntity u = new UserEntity();
        u.setId(UUID.randomUUID());
        u.setOidcId(subject);
        u.setEmail(email);
        u.setUsername(name);
        u.setRole(this.config.user().defaultRole());
        u.setCreatedAt(OffsetDateTime.now());
        u.setLastLogin(OffsetDateTime.now());
        return userStore.persist(u);
    }
    @Override
    public UserEntity create(UserEntity userEntity) {
        Objects.requireNonNull(userEntity, "userEntity must not be null");
        if (userEntity.getId() == null) {
            userEntity.setId(UUID.randomUUID());
        }
        if (userEntity.getCreatedAt() == null) {
            userEntity.setCreatedAt(OffsetDateTime.now());
        }
        // Garde-fous d'unicité
        if (userEntity.getOidcId() != null
                && userStore.findByOidcId(userEntity.getOidcId()).isPresent()) {
            throw new IllegalStateException(
                    "User already exists with oidcId: " + userEntity.getOidcId());
        }
        if (userEntity.getUsername() != null
                && userStore.findByUsername(userEntity.getUsername()).isPresent()) {
            throw new IllegalStateException(
                    "User already exists with username: " + userEntity.getUsername());
        }
        return userStore.persist(userEntity);
    }

    @Override
    public UserEntity findByOidcId(String oidcId) {
        return userStore.findByOidcId(oidcId)
                .orElseThrow(() -> new NoSuchElementException(
                        "No user with oidcId: " + oidcId));
    }

    @Override
    public UserEntity findByEmail(String email) {
        Objects.requireNonNull(email, "email must not be null");
        return userStore.findAll().stream()
                .filter(u -> email.equalsIgnoreCase(u.getEmail()))
                .findFirst()
                .orElseThrow(() -> new NoSuchElementException(
                        "No user with email: " + email));
    }

    @Override
    public UserEntity findByUsername(String username) {
        return userStore.findByUsername(username)
                .orElseThrow(() -> new NoSuchElementException(
                        "No user with username: " + username));
    }

    @Override
    public UserEntity findById(UUID id) {
        return userStore.findById(id)
                .orElseThrow(() -> new NoSuchElementException(
                        "No user with id: " + id));
    }

    @Override
    public UserEntity update(UserEntity userEntity) {
        Objects.requireNonNull(userEntity, "userEntity must not be null");
        Objects.requireNonNull(userEntity.getId(), "id must not be null");
        return userStore.update(userEntity);
    }

    @Override
    public void deleteById(UUID id) {
        // Le UserStore actuel n'expose pas de delete — à ajouter au SPI
        throw new UnsupportedOperationException(
                "UserStore.deleteById not yet defined in SPI");
    }

    @Override
    public void banUser(UUID userId) {
        UserEntity user = findById(userId);
        user.setState(UserStateEnum.BLOCKED);
        userStore.update(user);
    }

    @Override
    public void unbanUser(UUID userId) {
        UserEntity user = findById(userId);
        user.setState(UserStateEnum.ACTIVE);
        userStore.update(user);
    }

    @Override
    public void updateLastLogin(UserEntity userEntity) {
        Objects.requireNonNull(userEntity, "userEntity must not be null");
        userEntity.setLastLogin(OffsetDateTime.now());
        userStore.update(userEntity);
    }
}

