package net.norskel.auth.module.runtime.spi;

import net.norskel.auth.module.runtime.entities.ApiKeyEntity;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * ApiKeyStore
 *
 * @author Norskel
 * @since 16.04.2026
 **/
public interface ApiKeyStore {
    Optional<ApiKeyEntity> findById(UUID id);

    List<ApiKeyEntity> findByUser(UUID userId);

    ApiKeyEntity persist(ApiKeyEntity apiKeyEntity);

    ApiKeyEntity update(ApiKeyEntity apiKeyEntity);

}
