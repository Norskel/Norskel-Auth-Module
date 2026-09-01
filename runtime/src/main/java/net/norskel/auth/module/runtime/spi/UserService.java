package net.norskel.auth.module.runtime.spi;

import net.norskel.auth.module.runtime.entities.UserEntity;
import net.norskel.auth.module.runtime.enums.UserTypeEnum;

import java.util.Collection;
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

    /**
     * As {@link #upsertFromOidc(String, Object, Object)}, also syncing the avatar
     * URL read from the identity provider.
     *
     * <p>Defaulted so existing implementations keep compiling; override it to
     * store the avatar, since the default drops it.
     *
     * @param avatarUrl {@code null} when the provider sent no avatar claim, which
     *                  must leave the stored avatar untouched rather than clear it.
     */
    default UserEntity upsertFromOidc(String subject, Object email, Object name, Object avatarUrl) {
        return upsertFromOidc(subject, email, name);
    }

    /**
     * As {@link #upsertFromOidc(String, Object, Object, Object)}, also deriving the
     * stored role from the roles the identity provider granted for this login.
     *
     * <p>Defaulted so existing implementations keep compiling; the default ignores
     * {@code ssoRoles}, leaving the stored role as it was.
     *
     * @param ssoRoles every role the provider granted, may be empty, never
     *                 {@code null}. Which of them may reach the row — and with
     *                 what priority — is a configuration matter, not the caller's.
     */
    default UserEntity upsertFromOidc(String subject, Object email, Object name, Object avatarUrl,
                                      Collection<String> ssoRoles) {
        return upsertFromOidc(subject, email, name, avatarUrl);
    }

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

    /**
     * All users of the given type.
     *
     * <p>Defaulted on top of {@link #findAll()} so existing implementations keep
     * compiling; override it with a targeted query when the user table is large.
     */
    default List<UserEntity> findByType(UserTypeEnum type) {
        return findAll().stream()
                .filter(u -> u.getType() == type)
                .toList();
    }

    /**
     * Finds the {@code SERVICE} user with this name, creating it if absent.
     *
     * @param role the role the service holds; when the service already exists
     *             with a different role the call is rejected rather than
     *             silently changing its privileges.
     */
    UserEntity findOrCreateService(String serviceName, String role);

    /**
     * As {@link #findOrCreateService(String, String)}, recording which identity
     * created the service when it did not already exist.
     */
    default UserEntity findOrCreateService(String serviceName, String role, UUID createdBy) {
        return findOrCreateService(serviceName, role);
    }
}
