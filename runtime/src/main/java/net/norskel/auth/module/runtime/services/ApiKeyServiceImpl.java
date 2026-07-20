package net.norskel.auth.module.runtime.services;

import io.quarkus.arc.DefaultBean;
import io.smallrye.jwt.build.Jwt;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import net.norskel.auth.module.runtime.config.AuthBuildTimeConfig;
import net.norskel.auth.module.runtime.config.AuthRuntimeConfig;
import net.norskel.auth.module.runtime.entities.ApiKeyEntity;
import net.norskel.auth.module.runtime.enums.UserStateEnum;
import net.norskel.auth.module.runtime.spi.ApiKeyService;
import net.norskel.auth.module.runtime.spi.ApiKeyStore;
import net.norskel.auth.module.runtime.spi.UserService;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.UUID;

/**
 * ApiKeyServiceImpl
 *
 * @author Norskel
 * @since 16.04.2026
 **/
@DefaultBean
@ApplicationScoped
public class ApiKeyServiceImpl implements ApiKeyService {

    @Inject
    ApiKeyStore apiKeyStore;

    @Inject
    UserService userService;

    @Inject
    AuthBuildTimeConfig buildTimeConfig;

    @Inject
    AuthRuntimeConfig runtimeConfig;

    @Override
    public List<ApiKeyEntity> listByUser(UUID userId) {
        Objects.requireNonNull(userId, "userId must not be null");
        return apiKeyStore.findByUser(userId);
    }

    @Override
    public ApiKeyEntity getApiKey(UUID apiKey) {
        Objects.requireNonNull(apiKey, "apiKey id must not be null");
        return apiKeyStore.findById(apiKey)
                .orElseThrow(() -> new NoSuchElementException(
                        "No api key with id: " + apiKey));
    }

    @Override
    public IssuedApiKey create(UUID userId, String name, Duration lifetime) {
        Objects.requireNonNull(userId, "userId must not be null");

        Duration ttl = lifetime != null
                ? lifetime
                : runtimeConfig.apiToken().defaultTtl().orElse(null);
        if (ttl == null) {
            throw new IllegalArgumentException(
                    "lifetime is required (no norskel-auth.api-token.default-ttl configured)");
        }
        if (ttl.isZero() || ttl.isNegative()) {
            throw new IllegalArgumentException("lifetime must be positive");
        }

        // Vérifie que le user existe (lance NoSuchElementException sinon)
        var user = userService.findById(userId);
        if (user.getState() == UserStateEnum.BLOCKED) {
            throw new IllegalStateException("Cannot create token for banned user");
        }

        UUID jti = UUID.randomUUID();
        OffsetDateTime now = OffsetDateTime.now();
        OffsetDateTime exp = now.plus(ttl);

        ApiKeyEntity entity = new ApiKeyEntity();
        entity.setId(jti);
        entity.setUserId(userId);
        entity.setName(name);
        entity.setCreatedAt(now);
        entity.setExpiresAt(exp);
        entity.setRevoked(false);
        apiKeyStore.persist(entity);

        String token = Jwt.issuer(this.buildTimeConfig.apiTokenIssuer())
                .subject(userId.toString())
                .claim("token_name", name)
                .claim("auth_source", "api-key")
                .claim("jti", jti.toString())
                .issuedAt(now.toInstant())
                .expiresAt(exp.toInstant())
                .sign();

        return new IssuedApiKey(entity, token);
    }

    @Override
    public void revoke(UUID apiKey, UUID requestingUserId) {
        Objects.requireNonNull(apiKey, "apiKey id must not be null");
        Objects.requireNonNull(requestingUserId, "requestingUserId must not be null");

        ApiKeyEntity entity = getApiKey(apiKey);
        if (!entity.getUserId().equals(requestingUserId)) {
            // À adapter selon ta logique : un admin peut peut-être révoquer ?
            throw new SecurityException(
                    "User " + requestingUserId + " cannot revoke key " + apiKey);
        }
        if (entity.getRevoked()) return;

        entity.setRevoked(true);
        entity.setRevokedAt(OffsetDateTime.now());
        apiKeyStore.update(entity);
    }

    @Override
    public void revokeAllForUser(UUID userId) {
        Objects.requireNonNull(userId, "userId must not be null");
        OffsetDateTime now = OffsetDateTime.now();
        for (ApiKeyEntity key : apiKeyStore.findByUser(userId)) {
            if (!key.getRevoked()) {
                key.setRevoked(true);
                key.setRevokedAt(now);
                apiKeyStore.update(key);
            }
        }
    }

    @Override
    public boolean check(UUID apiKey) {
        if (apiKey == null) return false;
        return apiKeyStore.findById(apiKey)
                .filter(k -> !k.getRevoked())
                .filter(k -> k.getExpiresAt() == null
                        || k.getExpiresAt().isAfter(OffsetDateTime.now()))
                .isPresent();
    }

    @Override
    public void recordUsage(UUID apiKey) {
        if (apiKey == null) return;
        if (!runtimeConfig.apiToken().trackUsage()) return;

        apiKeyStore.findById(apiKey).ifPresent(key -> {
            OffsetDateTime now = OffsetDateTime.now();
            Duration throttle = runtimeConfig.apiToken().usageUpdateThrottle();
            OffsetDateTime last = key.getLastUsedAt();
            if (last == null || last.plus(throttle).isBefore(now)) {
                key.setLastUsedAt(now);
                apiKeyStore.update(key);
            }
        });
    }
}
