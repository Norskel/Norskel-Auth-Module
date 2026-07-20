package net.norskel.auth.module.runtime.spi;

import net.norskel.auth.module.runtime.entities.ApiKeyEntity;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

/**
 * ApiKeyService
 *
 * @author Norskel
 * @since 16.04.2026
 **/
public interface ApiKeyService {

    /**
     * Result of a key creation: the persisted metadata and the signed token.
     * The raw {@code token} is only available here, at creation time.
     */
    record IssuedApiKey(ApiKeyEntity apiKey, String token) {}

    List<ApiKeyEntity> listByUser(UUID userId);

    ApiKeyEntity getApiKey(UUID apiKey);

    /**
     * Creates and signs a new API key for the given user.
     *
     * @param lifetime the key lifetime; when {@code null}, the configured
     *                 {@code norskel-auth.api-token.default-ttl} is used.
     *                 If neither is set, creation is rejected.
     */
    IssuedApiKey create(UUID userId, String name, Duration lifetime);

    void revoke(UUID apiKey, UUID requestingUserId);

    void revokeAllForUser(UUID userId);

    boolean check(UUID apiKey);

    /**
     * Records that a key was just used (updates {@code lastUsedAt}), subject to
     * the {@code track-usage} flag and the {@code usage-update-throttle} window.
     */
    void recordUsage(UUID apiKey);

}
