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

    /**
     * As {@link #create(UUID, String, Duration)}, recording which identity
     * issued the key.
     *
     * <p>Defaulted so existing implementations keep working; they just record no
     * provenance. Override it to store {@code createdBy}.
     *
     * @param createdBy the acting identity, or {@code null} when a key is issued
     *                  programmatically rather than by a caller
     */
    default IssuedApiKey create(UUID userId, String name, Duration lifetime, UUID createdBy) {
        return create(userId, name, lifetime);
    }

    /** Every key owned by a user of type {@code SERVICE}. */
    List<ApiKeyEntity> listServiceKeys();

    /**
     * Convenience over {@link #create(UUID, String, Duration)}: resolves (or
     * creates) the {@code SERVICE} user called {@code serviceName}, then issues
     * an ordinary key owned by it.
     *
     * <p>The key is in no way special — it takes its role from the service user
     * like any other key, and blocking that user disables all of them at once.
     * Calling this repeatedly for one service issues additional keys, which is
     * how rotation works.
     *
     * @param serviceName the service identity; becomes its username
     * @param name        human-readable label for the key
     * @param role        role held by the service. Rejected with a conflict if
     *                    the service already exists with a different role.
     * @param lifetime    the key lifetime; when {@code null}, the configured
     *                    {@code norskel-auth.api-token.default-ttl} is used.
     *                    If neither is set, creation is rejected.
     */
    IssuedApiKey createServiceKey(String serviceName, String name, String role, Duration lifetime);

    /**
     * As {@link #createServiceKey(String, String, String, Duration)}, recording
     * which identity created the service and its key.
     */
    default IssuedApiKey createServiceKey(String serviceName, String name, String role,
                                          Duration lifetime, UUID createdBy) {
        return createServiceKey(serviceName, name, role, lifetime);
    }

    /**
     * Revokes a key regardless of ownership, for an administrator acting on
     * someone else's key. A service key is owned by its {@code SERVICE} user
     * like any other, but that user never calls in to revoke its own keys, so
     * this is in practice the only way to revoke one individually — the other
     * being to block the service row, which disables all of them.
     */
    void revokeAsAdmin(UUID apiKey);

    void revoke(UUID apiKey, UUID requestingUserId);

    void revokeAllForUser(UUID userId);

    boolean check(UUID apiKey);

    /**
     * Records that a key was just used (updates {@code lastUsedAt}), subject to
     * the {@code track-usage} flag and the {@code usage-update-throttle} window.
     */
    void recordUsage(UUID apiKey);

}
