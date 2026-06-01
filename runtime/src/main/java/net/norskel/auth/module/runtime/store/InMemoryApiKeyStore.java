package net.norskel.auth.module.runtime.store;

import io.quarkus.arc.DefaultBean;
import jakarta.enterprise.context.ApplicationScoped;
import net.norskel.auth.module.runtime.entities.ApiKeyEntity;
import net.norskel.auth.module.runtime.spi.ApiKeyStore;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ApiKeyStoreImpl
 *
 * @author Norskel
 * @since 16.04.2026
 **/
@DefaultBean
@ApplicationScoped
public class InMemoryApiKeyStore implements ApiKeyStore {

    private final Map<UUID, ApiKeyEntity> keys = new ConcurrentHashMap<>();

    @Override
    public Optional<ApiKeyEntity> findById(UUID id) {
        return Optional.ofNullable(keys.get(id));
    }

    @Override
    public List<ApiKeyEntity> findByUser(UUID userId) {
        if (userId == null) return List.of();
        return keys.values().stream()
                .filter(k -> userId.equals(k.getUserId()))
                .toList();
    }

    @Override
    public ApiKeyEntity persist(ApiKeyEntity apiKeyEntity) {
        Objects.requireNonNull(apiKeyEntity, "apiKeyEntity must not be null");
        if (apiKeyEntity.getId() == null) {
            apiKeyEntity.setId(UUID.randomUUID());
        }
        if (keys.putIfAbsent(apiKeyEntity.getId(), apiKeyEntity) != null) {
            throw new IllegalStateException(
                    "ApiKey already exists with id: " + apiKeyEntity.getId());
        }
        return apiKeyEntity;
    }

    @Override
    public ApiKeyEntity update(ApiKeyEntity apiKeyEntity) {
        Objects.requireNonNull(apiKeyEntity, "apiKeyEntity must not be null");
        Objects.requireNonNull(apiKeyEntity.getId(), "id must not be null on update");
        if (keys.replace(apiKeyEntity.getId(), apiKeyEntity) == null) {
            throw new NoSuchElementException(
                    "No api key found with id: " + apiKeyEntity.getId());
        }
        return apiKeyEntity;
    }
}
