package net.norskel.auth.module.runtime.spi;

import net.norskel.auth.module.runtime.entities.UserEntity;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * UserStore
 *
 * @author Norskel
 * @since 16.04.2026
 **/
public interface UserStore {

    Optional<UserEntity> findById(UUID id);

    Optional<UserEntity> findByOidcId(String oidcId);

    UserEntity persist(UserEntity userEntity);

    UserEntity update(UserEntity userEntity);

    List<UserEntity> findAll();

    Optional<UserEntity> findByUsername(String username);
}
