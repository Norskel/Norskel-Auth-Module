package net.norskel.auth.module.runtime;

import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.smallrye.jwt.runtime.auth.JsonWebTokenCredential;
import jakarta.enterprise.context.Dependent;
import jakarta.inject.Inject;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import net.norskel.auth.module.runtime.spi.ApiKeyService;
import org.eclipse.microprofile.jwt.JsonWebToken;

import java.util.UUID;
import java.util.function.Supplier;

/**
 * JwtSecurityIdentitySupplier
 *
 * @author Norskel
 * @since 30.03.2026
 **/
@Dependent
@Slf4j
public class JwtSecurityIdentitySupplier implements Supplier<SecurityIdentity> {

    @Setter
    private SecurityIdentity identity;

    @Inject
    ApiKeyService apiKeyService;


    @Override
    public SecurityIdentity get() {
        JsonWebToken jwt = (JsonWebToken) identity.getPrincipal();


        String jti = jwt.getTokenID();
        String subject = jwt.getSubject();
        String rawToken = identity.getCredential(JsonWebTokenCredential.class).getToken(); // String

        log.info("jti={}, subject={}, rawToken={}", jti, subject, rawToken);

        if (jti == null || jti.isBlank()) {
            throw new AuthenticationFailedException("Token not valid");
        }

        UUID tokenId;
        try {
            tokenId = UUID.fromString(jti);
        } catch (IllegalArgumentException e) {
            throw new AuthenticationFailedException("Token not valid");
        }

        if (!apiKeyService.check(tokenId)) {
            log.warn("Rejected revoked token jti={}", jti);
            throw new AuthenticationFailedException("Token has been revoked");
        }

        return QuarkusSecurityIdentity.builder(identity)
                .addRole("User")
                .build();
    }

}
