package net.norskel.auth.module.runtime;

import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import lombok.extern.slf4j.Slf4j;
import net.norskel.auth.module.runtime.entities.UserEntity;
import net.norskel.auth.module.runtime.enums.UserStateEnum;
import net.norskel.auth.module.runtime.enums.UserTypeEnum;
import net.norskel.auth.module.runtime.spi.ApiKeyService;
import net.norskel.auth.module.runtime.spi.UserService;
import org.eclipse.microprofile.jwt.JsonWebToken;

import java.util.UUID;

/**
 * JwtSecurityIdentitySupplier
 *
 * <p>Stateless: the identity to augment is passed in per call, so a single
 * application-scoped instance is shared across requests.
 *
 * @author Norskel
 * @since 30.03.2026
 **/
@ApplicationScoped
@Slf4j
public class JwtSecurityIdentitySupplier {

    @Inject
    ApiKeyService apiKeyService;

    @Inject
    UserService userService;

    public SecurityIdentity augment(SecurityIdentity identity) {
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

        // 3. The subject carries the owning user id (set at creation). One path
        // for every key: a service is a user row, so there is no second shape
        // of identity to build and no discriminator to branch on.
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

        // 4. A blocked owner's keys must stop working. This is what gives
        // services a kill switch: banning the service row disables every key
        // it owns at once.
        if (user.getState() == UserStateEnum.BLOCKED) {
            log.warn("Rejected API key for blocked owner id={} type={}",
                    userId, user.getType());
            throw new AuthenticationFailedException("User is banned");
        }

        // 5. Build the identity. The only difference between a person and a
        // service is what we advertise about them, not how they are resolved.
        boolean isService = user.getType() == UserTypeEnum.SERVICE;

        QuarkusSecurityIdentity.Builder builder = QuarkusSecurityIdentity.builder(identity)
                .addAttribute(AuthAttributes.USER_ID, user.getId())
                .addAttribute(AuthAttributes.USER, user)
                .addAttribute(AuthAttributes.AUTH_SOURCE, isService
                        ? AuthAttributes.SOURCE_SERVICE_API_KEY
                        : AuthAttributes.SOURCE_API_KEY);

        if (isService) {
            builder.addAttribute(AuthAttributes.SERVICE_NAME, user.getUsername());
        }

        String role = user.getRole();
        if (role != null && !role.isBlank()) {
            builder.addRole(role);
        } else if (isService) {
            // A service with no role would authenticate with no authority at all.
            log.warn("Rejected service key with no role serviceName={}", user.getUsername());
            throw new AuthenticationFailedException("Token not valid");
        }

        return builder.build();
    }


}
