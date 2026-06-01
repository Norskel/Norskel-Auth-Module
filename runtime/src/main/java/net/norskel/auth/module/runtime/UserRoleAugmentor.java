package net.norskel.auth.module.runtime;

import io.quarkus.oidc.AccessTokenCredential;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.SecurityIdentityAugmentor;
import io.quarkus.smallrye.jwt.runtime.auth.JsonWebTokenCredential;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
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
    Instance<JwtSecurityIdentitySupplier> jwtSecurityIdentitySuppliers;

    @Inject
    Instance<OIDCSecurityIdentitySupplier> oidcSecurityIdentitySuppliers;

    @Override
    public int priority() {
        return 100;
    }

    @Override
    public Uni<SecurityIdentity> augment(SecurityIdentity identity,
                                         AuthenticationRequestContext context) {

        log.info("Augmenting identity: {}", identity);
        if (identity.getCredential(AccessTokenCredential.class) != null) {
            log.info("Augmenting with OIDC identity");
            final OIDCSecurityIdentitySupplier identitySupplier = this.oidcSecurityIdentitySuppliers.get();
            identitySupplier.setIdentity(identity);
            return context.runBlocking(identitySupplier)
                    .onFailure().transform(ex -> {
                        log.warn("OIDC auth rejected: {}", ex.getMessage());
                        return new AuthenticationFailedException("OIDC auth failed", ex);
                    });
        }
        if (identity.getCredential(JsonWebTokenCredential.class) != null) {
            log.info("Augmenting with JWT identity");
            final JwtSecurityIdentitySupplier identitySupplier = this.jwtSecurityIdentitySuppliers.get();
            identitySupplier.setIdentity(identity);
            return context.runBlocking(identitySupplier)
                    .onFailure().transform(ex -> {
                        log.warn("JWT auth rejected: {}", ex.getMessage());
                        return new AuthenticationFailedException("JWT auth failed", ex);
                    });
        }
        return Uni.createFrom().item(identity);
    }
}
