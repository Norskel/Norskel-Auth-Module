package net.norskel.auth.module.runtime;

import io.quarkus.security.UnauthorizedException;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import net.norskel.auth.module.runtime.entities.UserEntity;

import java.util.Optional;
import java.util.UUID;

/**
 * CurrentUser
 *
 * <p>Typed view of the caller of the current request, built from the attributes this
 * extension puts on the {@code SecurityIdentity} (see {@link AuthAttributes}). Inject it
 * instead of reading those attributes by name, so application code does not depend on
 * how the identity was produced (OIDC, personal API key or service API key).
 *
 * <p>Anonymous requests, and identities this extension did not augment, have no user:
 * {@link #user()} is empty and {@link #require()} throws {@link UnauthorizedException}.
 *
 * @author Norskel
 * @since 27.10.2026
 **/
@RequestScoped
public class CurrentUser {

    @Inject
    SecurityIdentity identity;

    /** The resolved user, if the caller is authenticated through this extension. */
    public Optional<UserEntity> user() {
        if (identity.isAnonymous()) {
            return Optional.empty();
        }
        return Optional.ofNullable(identity.getAttribute(AuthAttributes.USER));
    }

    /** The resolved user, or a 401 when there is none. */
    public UserEntity require() {
        return user().orElseThrow(() -> new UnauthorizedException("No authenticated user"));
    }

    /** The caller's user id, if any. */
    public Optional<UUID> id() {
        return user().map(UserEntity::getId);
    }

    /** Which mechanism authenticated the caller: one of the {@code AuthAttributes.SOURCE_*} values. */
    public Optional<String> authSource() {
        if (identity.isAnonymous()) {
            return Optional.empty();
        }
        return Optional.ofNullable(identity.getAttribute(AuthAttributes.AUTH_SOURCE));
    }

    /** True when the caller is a service, i.e. used a service API key. */
    public boolean isService() {
        return authSource().filter(AuthAttributes.SOURCE_SERVICE_API_KEY::equals).isPresent();
    }

    /** The service name, present only for service API keys. */
    public Optional<String> serviceName() {
        if (!isService()) {
            return Optional.empty();
        }
        return Optional.ofNullable(identity.getAttribute(AuthAttributes.SERVICE_NAME));
    }

    /** Whether the caller holds the given role. */
    public boolean hasRole(String role) {
        return identity.hasRole(role);
    }
}
