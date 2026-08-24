package net.norskel.auth.module.runtime.store;

import io.quarkus.arc.DefaultBean;
import jakarta.enterprise.context.ApplicationScoped;
import net.norskel.auth.module.runtime.entities.UserEntity;
import net.norskel.auth.module.runtime.spi.UserStore;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * UserStoreImpl
 *
 * @author Norskel
 * @since 16.04.2026
 **/
@DefaultBean
@ApplicationScoped
public class InMemoryUserStore implements UserStore {

    private final Map<UUID, UserEntity> users = new ConcurrentHashMap<>();

    @Override
    public Optional<UserEntity> findById(UUID id) {
        return Optional.ofNullable(users.get(id));
    }

    @Override
    public Optional<UserEntity> findByOidcId(String oidcId) {
        if (oidcId == null) return Optional.empty();
        return users.values().stream()
                .filter(u -> oidcId.equals(u.getOidcId()))
                .findFirst();
    }

    @Override
    public Optional<UserEntity> findByUsername(String username) {
        if (username == null) return Optional.empty();
        return users.values().stream()
                .filter(u -> username.equals(u.getUsername()))
                .findFirst();
    }

    @Override
    public List<UserEntity> findAll() {
        return new ArrayList<>(users.values());
    }

    @Override
    public UserEntity persist(UserEntity userEntity) {
        Objects.requireNonNull(userEntity, "userEntity must not be null");
        if (userEntity.getId() == null) {
            userEntity.setId(UUID.randomUUID());
        }
        if (users.putIfAbsent(userEntity.getId(), userEntity) != null) {
            throw new IllegalStateException(
                    "User already exists with id: " + userEntity.getId());
        }
        return userEntity;
    }

    @Override
    public UserEntity update(UserEntity userEntity) {
        Objects.requireNonNull(userEntity, "userEntity must not be null");
        Objects.requireNonNull(userEntity.getId(), "id must not be null on update");
        if (users.replace(userEntity.getId(), userEntity) == null) {
            throw new NoSuchElementException(
                    "No user found with id: " + userEntity.getId());
        }
        return userEntity;
    }

    @Override
    public boolean deleteById(UUID id) {
        if (id == null) return false;
        return users.remove(id) != null;
    }
}