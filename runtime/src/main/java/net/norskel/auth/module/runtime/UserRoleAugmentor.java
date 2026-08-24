package net.norskel.auth.module.runtime;

import io.quarkus.oidc.AccessTokenCredential;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.SecurityIdentityAugmentor;
import io.quarkus.smallrye.jwt.runtime.auth.JsonWebTokenCredential;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import lombok.extern.slf4j.Slf4j;

/**
 * UserRoleAugmentor
 *
 * @author Norskel
 * @since 30.03.2026
 **/
@ApplicationScoped
@Slf4j
public class UserRoleAugmentor implements SecurityIdentityAugmentor {

    @Inject
    JwtSecurityIdentitySupplier jwtSupplier;

    @Inject
    OIDCSecurityIdentitySupplier oidcSupplier;

    @Override
    public int priority() {
        return 100;
    }

    @Override
    public Uni<SecurityIdentity> augment(SecurityIdentity identity,
                                         AuthenticationRequestContext context) {

        if (identity.getCredential(AccessTokenCredential.class) != null) {
            log.debug("Augmenting with OIDC identity");
            return context.runBlocking(() -> oidcSupplier.augment(identity))
                    .onFailure().transform(ex -> {
                        log.warn("OIDC auth rejected: {}", ex.getMessage());
                        return new AuthenticationFailedException("OIDC auth failed", ex);
                    });
        }
        if (identity.getCredential(JsonWebTokenCredential.class) != null) {
            log.debug("Augmenting with JWT identity");
            return context.runBlocking(() -> jwtSupplier.augment(identity))
                    .onFailure().transform(ex -> {
                        log.warn("JWT auth rejected: {}", ex.getMessage());
                        return new AuthenticationFailedException("JWT auth failed", ex);
                    });
        }
        return Uni.createFrom().item(identity);
    }
}
