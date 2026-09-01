package net.norskel.auth.module.runtime.services;

import io.quarkus.arc.DefaultBean;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import net.norskel.auth.module.runtime.config.AuthRuntimeConfig;
import net.norskel.auth.module.runtime.entities.UserEntity;
import net.norskel.auth.module.runtime.enums.UserStateEnum;
import net.norskel.auth.module.runtime.enums.UserTypeEnum;
import net.norskel.auth.module.runtime.exceptions.AuthConflictException;
import net.norskel.auth.module.runtime.exceptions.AuthValidationException;
import net.norskel.auth.module.runtime.exceptions.AuthNotFoundException;
import net.norskel.auth.module.runtime.spi.UserService;
import net.norskel.auth.module.runtime.spi.UserStore;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
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
        return upsertFromOidc(subject, email, name, null);
    }

    @Override
    public UserEntity upsertFromOidc(String subject, Object email, Object name, Object avatarUrl) {
        return upsertFromOidc(subject, email, name, avatarUrl, Set.of());
    }

    @Override
    public UserEntity upsertFromOidc(String subject, Object email, Object name, Object avatarUrl,
                                     Collection<String> ssoRoles) {
        Objects.requireNonNull(subject);
        String emailStr = email != null ? email.toString() : null;
        String nameStr = name != null ? name.toString() : null;
        String avatarStr = avatarUrl != null ? avatarUrl.toString() : null;
        Collection<String> roles = ssoRoles != null ? ssoRoles : Set.of();

        return userStore.findByOidcId(subject)
                .map(existing -> syncIfChanged(existing, emailStr, nameStr, avatarStr, roles))
                .orElseGet(() -> {
                    if (!config.user().autoCreateOnOidc()) {
                        throw new AuthNotFoundException(
                                "Unknown OIDC user and auto-create is disabled: " + subject);
                    }
                    return createFromOidc(subject, emailStr, nameStr, avatarStr, roles);
                });
    }

    private UserEntity syncIfChanged(UserEntity user, String email, String name, String avatarUrl,
                                     Collection<String> ssoRoles) {
        boolean changed = false;
        if (email != null && !email.equals(user.getEmail())) {
            user.setEmail(email); changed = true;
        }
        if (name != null && !name.equals(user.getUsername())) {
            // The provider can rename a person at any time, so the collision
            // guard belongs on every login and not only on the first one.
            assertNoServiceCollision(name, user.getId());
            user.setUsername(name); changed = true;
        }
        if (avatarUrl != null && !avatarUrl.equals(user.getAvatarUrl())) {
            // The provider is authoritative on the avatar exactly as it is on the
            // email: a picture changed there must show up here on the next login.
            user.setAvatarUrl(avatarUrl); changed = true;
        }
        String role = roleFromSso(ssoRoles, user.getRole());
        if (role != null && !role.equals(user.getRole())) {
            user.setRole(role); changed = true;
        }
        return changed ? userStore.update(user) : user;
    }

    /**
     * The role the identity provider dictates for this login, {@code null} to leave
     * the stored one alone.
     *
     * <p>Only the roles named in {@code norskel-auth.user.db-role-from-sso} are
     * governed here, the first of that list winning when the provider granted
     * several: the row holds a single role, so the arbitration has to be explicit
     * rather than depend on the order the claims happened to come in.
     *
     * <p>Over that list the provider is authoritative in both directions — losing a
     * governed role there brings the row back to {@link
     * AuthRuntimeConfig.UserRuntimeConfig#defaultRole()}, since a privilege revoked
     * at the IdP must not survive in our table. A stored role outside the list is
     * left untouched: it was granted by hand and is not the provider's to revoke.
     *
     * @param currentRole the stored role, {@code null} when creating the row.
     */
    private String roleFromSso(Collection<String> ssoRoles, String currentRole) {
        List<String> governed = config.user().dbRoleFromSso().orElseGet(List::of);
        if (governed.isEmpty()) {
            return null;
        }
        for (String candidate : governed) {
            if (ssoRoles.contains(candidate)) {
                return candidate;
            }
        }
        return governed.contains(currentRole) ? config.user().defaultRole() : null;
    }

    private UserEntity createFromOidc(String subject, String email, String name, String avatarUrl,
                                      Collection<String> ssoRoles) {
        assertNoServiceCollision(name, null);

        UserEntity u = new UserEntity();
        u.setId(UUID.randomUUID());
        u.setType(UserTypeEnum.HUMAN);
        u.setState(UserStateEnum.ACTIVE);
        u.setOidcId(subject);
        u.setEmail(email);
        u.setUsername(name);
        u.setAvatarUrl(avatarUrl);
        String role = roleFromSso(ssoRoles, null);
        u.setRole(role != null ? role : this.config.user().defaultRole());
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
        if (userEntity.getType() == null) {
            userEntity.setType(UserTypeEnum.HUMAN);
        }
        if (userEntity.getState() == null) {
            userEntity.setState(UserStateEnum.ACTIVE);
        }
        validateForType(userEntity);
        // Garde-fous d'unicité
        if (userEntity.getOidcId() != null
                && userStore.findByOidcId(userEntity.getOidcId()).isPresent()) {
            throw new AuthConflictException(
                    "User already exists with oidcId: " + userEntity.getOidcId());
        }
        assertUsernameFree(userEntity.getUsername(), null);
        return userStore.persist(userEntity);
    }

    /**
     * Enforces the per-type field rules that bean validation cannot express:
     * a person needs an email and an OIDC subject, a service must have neither
     * and must carry a role, since a service key takes its authority from the
     * identity.
     */
    private static void validateForType(UserEntity u) {
        if (u.getUsername() == null || u.getUsername().isBlank()) {
            throw new AuthValidationException("username is required");
        }
        if (u.getType() == UserTypeEnum.SERVICE) {
            if (u.getOidcId() != null) {
                throw new AuthValidationException(
                        "a SERVICE user cannot have an oidcId: it never logs in through OIDC");
            }
            if (u.getEmail() != null) {
                throw new AuthValidationException("a SERVICE user cannot have an email");
            }
            if (u.getRole() == null || u.getRole().isBlank()) {
                throw new AuthValidationException(
                        "role is required for a SERVICE user (its keys inherit it)");
            }
        } else {
            if (u.getOidcId() == null || u.getOidcId().isBlank()) {
                throw new AuthValidationException("oidcId is required for a HUMAN user");
            }
            if (u.getEmail() == null || u.getEmail().isBlank()) {
                throw new AuthValidationException("email is required for a HUMAN user");
            }
        }
    }

    /**
     * Refuses a username already taken by a {@code SERVICE} row.
     *
     * <p>Usernames on the OIDC paths come from the identity provider, which we do
     * not control, so this is deliberately narrower than the global uniqueness
     * {@link #create(UserEntity)} demands: two people may share a display name,
     * but nobody may shadow a service identity in logs and audits.
     *
     * @param selfId the row being written, excluded from the scan; {@code null}
     *               when creating.
     */
    private void assertNoServiceCollision(String username, UUID selfId) {
        if (username == null) return;
        findColliding(username, selfId)
                .filter(other -> other.getType() == UserTypeEnum.SERVICE)
                .ifPresent(other -> {
                    throw new AuthConflictException(
                            "OIDC username collides with the service identity: " + username);
                });
    }

    /**
     * Refuses a username already taken by any other row.
     *
     * @param selfId the row being written, excluded from the scan.
     */
    private void assertUsernameFree(String username, UUID selfId) {
        if (username == null) return;
        findColliding(username, selfId).ifPresent(other -> {
            throw new AuthConflictException(
                    "User already exists with username: " + username);
        });
    }

    /**
     * Any row other than {@code selfId} holding this username.
     *
     * <p>Scans rather than using {@link UserStore#findByUsername(String)}: that
     * returns a single arbitrary match, which for an in-place store can be the
     * very row being updated, hiding the real collision behind it. A
     * database-backed {@code UserStore} should carry a unique index on username —
     * this check narrows the window, it does not close it.
     */
    private Optional<UserEntity> findColliding(String username, UUID selfId) {
        return userStore.findAll().stream()
                .filter(other -> username.equals(other.getUsername()))
                .filter(other -> selfId == null || !selfId.equals(other.getId()))
                .findFirst();
    }

    @Override
    public UserEntity findOrCreateService(String serviceName, String role) {
        return findOrCreateService(serviceName, role, null);
    }

    @Override
    public UserEntity findOrCreateService(String serviceName, String role, UUID createdBy) {
        if (serviceName == null || serviceName.isBlank()) {
            throw new AuthValidationException("serviceName is required");
        }
        if (role == null || role.isBlank()) {
            throw new AuthValidationException("role is required for a service");
        }

        Optional<UserEntity> existing = userStore.findByUsername(serviceName);
        if (existing.isPresent()) {
            UserEntity found = existing.get();
            if (found.getType() != UserTypeEnum.SERVICE) {
                throw new AuthConflictException(
                        "A user already exists with username: " + serviceName);
            }
            if (!role.equals(found.getRole())) {
                // Changing privileges as a side effect of minting a key would be
                // far too easy to do by accident.
                throw new AuthConflictException(
                        "Service '" + serviceName + "' already exists with role '"
                                + found.getRole() + "'; update the user to change it");
            }
            return found;
        }

        UserEntity svc = new UserEntity();
        svc.setId(UUID.randomUUID());
        svc.setType(UserTypeEnum.SERVICE);
        svc.setState(UserStateEnum.ACTIVE);
        svc.setUsername(serviceName);
        svc.setRole(role);
        svc.setCreatedAt(OffsetDateTime.now());
        svc.setCreatedBy(createdBy);
        return userStore.persist(svc);
    }

    @Override
    public UserEntity findByOidcId(String oidcId) {
        return userStore.findByOidcId(oidcId)
                .orElseThrow(() -> new AuthNotFoundException(
                        "No user with oidcId: " + oidcId));
    }

    @Override
    public UserEntity findByEmail(String email) {
        Objects.requireNonNull(email, "email must not be null");
        return userStore.findAll().stream()
                .filter(u -> email.equalsIgnoreCase(u.getEmail()))
                .findFirst()
                .orElseThrow(() -> new AuthNotFoundException(
                        "No user with email: " + email));
    }

    @Override
    public UserEntity findByUsername(String username) {
        return userStore.findByUsername(username)
                .orElseThrow(() -> new AuthNotFoundException(
                        "No user with username: " + username));
    }

    @Override
    public UserEntity findById(UUID id) {
        return userStore.findById(id)
                .orElseThrow(() -> new AuthNotFoundException(
                        "No user with id: " + id));
    }

    /**
     * {@inheritDoc}
     *
     * <p>Re-checks the per-type invariants and username uniqueness. Validating
     * only on create is what a single-table design cannot afford: an update that
     * puts an email on a {@code SERVICE} row, or renames a person onto a
     * service's username, breaks the very properties the shared table relies on.
     * {@link #validateForType(UserEntity)} is a check on the resulting state, so
     * it needs no before/after comparison — which matters because an in-place
     * store has already applied the caller's mutations by the time we are called.
     */
    @Override
    public UserEntity update(UserEntity userEntity) {
        Objects.requireNonNull(userEntity, "userEntity must not be null");
        Objects.requireNonNull(userEntity.getId(), "id must not be null");
        validateForType(userEntity);
        assertUsernameFree(userEntity.getUsername(), userEntity.getId());
        return userStore.update(userEntity);
    }

    @Override
    public void deleteById(UUID id) {
        Objects.requireNonNull(id, "id must not be null");
        if (!userStore.deleteById(id)) {
            throw new AuthNotFoundException("No user with id: " + id);
        }
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

