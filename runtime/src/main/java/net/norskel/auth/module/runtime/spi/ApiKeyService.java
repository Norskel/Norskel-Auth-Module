package net.norskel.auth.module.runtime.spi;

import net.norskel.auth.module.runtime.entities.ApiKeyEntity;

import java.util.List;
import java.util.UUID;

/**
 * ApiKeyService
 *
 * @author Norskel
 * @since 16.04.2026
 **/
public interface ApiKeyService {

    List<ApiKeyEntity> listByUser(UUID userId);

    ApiKeyEntity getApiKey(UUID apiKey);

    String create(UUID userId, String name, int lifetimeDays);

    void revoke(UUID apiKey, UUID requestingUserId);

    void revokeAllForUser(UUID userId);

    boolean check(UUID apiKey);

}
