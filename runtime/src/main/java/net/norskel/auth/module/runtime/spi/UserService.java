package net.norskel.auth.module.runtime.spi;

import net.norskel.auth.module.runtime.entities.UserEntity;

import java.util.List;
import java.util.UUID;

/**
 * UserService
 *
 * @author Norskel
 * @since 16.04.2026
 **/
public interface UserService {

    List<UserEntity> findAll();

    UserEntity upsertFromOidc(String subject, Object email, Object name);

    UserEntity create(UserEntity userEntity);

    UserEntity findByOidcId(String oidcId);

    UserEntity findByEmail(String email);

    UserEntity findByUsername(String username);

    UserEntity findById(UUID id);

    UserEntity update(UserEntity userEntity);

    void deleteById(UUID id);

    void banUser(UUID userId);

    void unbanUser(UUID userId);

    void updateLastLogin(UserEntity userEntity);
}
