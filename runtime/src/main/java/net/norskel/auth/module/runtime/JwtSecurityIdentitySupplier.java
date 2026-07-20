package net.norskel.auth.module.runtime;

import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import jakarta.enterprise.context.Dependent;
import jakarta.inject.Inject;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import net.norskel.auth.module.runtime.entities.UserEntity;
import net.norskel.auth.module.runtime.enums.UserStateEnum;
import net.norskel.auth.module.runtime.spi.ApiKeyService;
import net.norskel.auth.module.runtime.spi.UserService;
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

    @Inject
    UserService userService;

    @Override
    public SecurityIdentity get() {
        JsonWebToken jwt = (JsonWebToken) identity.getPrincipal();

        String jti = jwt.getTokenID();
        log.debug("Augmenting API-key identity jti={}", jti);

        // 1. The jti is the persisted API-key id — validate its format
        if (jti == null || jti.isBlank()) {
            throw new AuthenticationFailedException("Token not valid");
        }
        UUID tokenId;
        try {
            tokenId = UUID.fromString(jti);
        } catch (IllegalArgumentException e) {
            throw new AuthenticationFailedException("Token not valid");
        }

        // 2. Reject revoked / expired keys (checked against the store)
        if (!apiKeyService.check(tokenId)) {
            log.warn("Rejected revoked or expired token jti={}", jti);
            throw new AuthenticationFailedException("Token has been revoked");
        }

        // 2b. Record usage (throttled, opt-out via config)
        apiKeyService.recordUsage(tokenId);

        // 3. The subject carries the owning user id (set at creation)
        UUID userId;
        try {
            userId = UUID.fromString(jwt.getSubject());
        } catch (IllegalArgumentException | NullPointerException e) {
            throw new AuthenticationFailedException("Token not valid");
        }

        UserEntity user;
        try {
            user = userService.findById(userId);
        } catch (Exception e) {
            log.warn("API key references unknown user id={}", userId);
            throw new AuthenticationFailedException("User not found");
        }

        // 4. A banned user's keys must stop working
        if (user.getState() == UserStateEnum.BLOCKED) {
            log.warn("Rejected API key for banned user id={}", userId);
            throw new AuthenticationFailedException("User is banned");
        }

        // 5. Build a unified identity mirroring the OIDC flow
        QuarkusSecurityIdentity.Builder builder = QuarkusSecurityIdentity.builder(identity)
                .addAttribute("user_id", user.getId())
                .addAttribute("user", user)
                .addAttribute("auth_source", "api-key");

        String role = user.getRole();
        if (role != null && !role.isBlank()) {
            builder.addRole(role);
        }

        return builder.build();
    }

}
