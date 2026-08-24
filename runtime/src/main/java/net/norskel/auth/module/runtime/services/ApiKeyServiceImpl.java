package net.norskel.auth.module.runtime.services;

import io.quarkus.arc.DefaultBean;
import io.smallrye.jwt.build.Jwt;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import net.norskel.auth.module.runtime.AuthAttributes;
import net.norskel.auth.module.runtime.config.AuthBuildTimeConfig;
import net.norskel.auth.module.runtime.config.AuthRuntimeConfig;
import net.norskel.auth.module.runtime.entities.ApiKeyEntity;
import net.norskel.auth.module.runtime.entities.UserEntity;
import net.norskel.auth.module.runtime.enums.UserStateEnum;
import net.norskel.auth.module.runtime.enums.UserTypeEnum;
import net.norskel.auth.module.runtime.exceptions.AuthConflictException;
import net.norskel.auth.module.runtime.exceptions.AuthForbiddenException;
import net.norskel.auth.module.runtime.exceptions.AuthNotFoundException;
import net.norskel.auth.module.runtime.exceptions.AuthValidationException;
import net.norskel.auth.module.runtime.spi.ApiKeyService;
import net.norskel.auth.module.runtime.spi.ApiKeyStore;
import net.norskel.auth.module.runtime.spi.UserService;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
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
                .orElseThrow(() -> new AuthNotFoundException(
                        "No api key with id: " + apiKey));
    }

    @Override
    public IssuedApiKey create(UUID userId, String name, Duration lifetime) {
        return create(userId, name, lifetime, null);
    }

    @Override
    public IssuedApiKey create(UUID userId, String name, Duration lifetime, UUID createdBy) {
        Objects.requireNonNull(userId, "userId must not be null");

        Duration ttl = resolveTtl(lifetime);

        // Vérifie que le user existe (lance AuthNotFoundException sinon)
        var user = userService.findById(userId);
        if (user.getState() == UserStateEnum.BLOCKED) {
            throw new AuthConflictException("Cannot create token for banned user");
        }

        UUID jti = UUID.randomUUID();
        OffsetDateTime now = OffsetDateTime.now();
        OffsetDateTime exp = now.plus(ttl);

        ApiKeyEntity entity = new ApiKeyEntity();
        entity.setId(jti);
        entity.setUserId(userId);
        entity.setName(name);
        entity.setCreatedAt(now);
        entity.setCreatedBy(createdBy);
        entity.setExpiresAt(exp);
        entity.setRevoked(false);
        apiKeyStore.persist(entity);

        String token = signToken(jti, userId.toString(), name,
                AuthAttributes.SOURCE_API_KEY, now, exp);

        return new IssuedApiKey(entity, token);
    }

    @Override
    public List<ApiKeyEntity> listServiceKeys() {
        return userService.findByType(UserTypeEnum.SERVICE).stream()
                .map(svc -> apiKeyStore.findByUser(svc.getId()))
                .flatMap(List::stream)
                .toList();
    }

    @Override
    public IssuedApiKey createServiceKey(String serviceName, String name,
                                        String role, Duration lifetime) {
        return createServiceKey(serviceName, name, role, lifetime, null);
    }

    @Override
    public IssuedApiKey createServiceKey(String serviceName, String name, String role,
                                         Duration lifetime, UUID createdBy) {
        // No dedicated key shape, no uniqueness scan, no separate signing path:
        // resolve the service user and fall through to the ordinary flow. The
        // username uniqueness of the user store is what keeps service names
        // unambiguous.
        UserEntity service = userService.findOrCreateService(serviceName, role, createdBy);
        return create(service.getId(), name, lifetime, createdBy);
    }

    private Duration resolveTtl(Duration lifetime) {
        Duration ttl = lifetime != null
                ? lifetime
                : runtimeConfig.apiToken().defaultTtl().orElse(null);
        if (ttl == null) {
            throw new AuthValidationException(
                    "lifetime is required (no norskel-auth.api-token.default-ttl configured)");
        }
        if (ttl.isZero() || ttl.isNegative()) {
            throw new AuthValidationException("lifetime must be positive");
        }
        return ttl;
    }

    private String signToken(UUID jti, String subject, String name, String authSource,
                             OffsetDateTime now, OffsetDateTime exp) {
        return Jwt.issuer(this.buildTimeConfig.apiTokenIssuer())
                .subject(subject)
                .claim("token_name", name)
                .claim("auth_source", authSource)
                .claim("jti", jti.toString())
                .issuedAt(now.toInstant())
                .expiresAt(exp.toInstant())
                .sign();
    }

    @Override
    public void revoke(UUID apiKey, UUID requestingUserId) {
        Objects.requireNonNull(apiKey, "apiKey id must not be null");
        Objects.requireNonNull(requestingUserId, "requestingUserId must not be null");

        ApiKeyEntity entity = getApiKey(apiKey);
        if (!requestingUserId.equals(entity.getUserId())) {
            throw new AuthForbiddenException(
                    "User " + requestingUserId + " cannot revoke key " + apiKey);
        }
        markRevoked(entity);
    }

    @Override
    public void revokeAsAdmin(UUID apiKey) {
        Objects.requireNonNull(apiKey, "apiKey id must not be null");
        markRevoked(getApiKey(apiKey));
    }

    private void markRevoked(ApiKeyEntity entity) {
        if (Boolean.TRUE.equals(entity.getRevoked())) return;

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
