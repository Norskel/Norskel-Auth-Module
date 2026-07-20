package net.norskel.auth.module.runtime.services;

import net.norskel.auth.module.runtime.config.AuthBuildTimeConfig;
import net.norskel.auth.module.runtime.config.AuthRuntimeConfig;
import net.norskel.auth.module.runtime.entities.ApiKeyEntity;
import net.norskel.auth.module.runtime.entities.UserEntity;
import net.norskel.auth.module.runtime.enums.UserStateEnum;
import net.norskel.auth.module.runtime.spi.ApiKeyStore;
import net.norskel.auth.module.runtime.spi.UserService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ApiKeyServiceImplTest {

    @Mock
    ApiKeyStore apiKeyStore;

    @Mock
    UserService userService;

    @Mock
    AuthBuildTimeConfig buildTimeConfig;

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    AuthRuntimeConfig runtimeConfig;

    @InjectMocks
    ApiKeyServiceImpl service;

    // --- check ---

    @Test
    void check_returnsFalse_forNull() {
        assertFalse(service.check(null));
    }

    @Test
    void check_returnsFalse_whenKeyNotFound() {
        UUID id = UUID.randomUUID();
        when(apiKeyStore.findById(id)).thenReturn(Optional.empty());
        assertFalse(service.check(id));
    }

    @Test
    void check_returnsFalse_forRevokedKey() {
        UUID id = UUID.randomUUID();
        ApiKeyEntity k = new ApiKeyEntity();
        k.setRevoked(true);
        k.setExpiresAt(OffsetDateTime.now().plusDays(10));
        when(apiKeyStore.findById(id)).thenReturn(Optional.of(k));
        assertFalse(service.check(id));
    }

    @Test
    void check_returnsFalse_forExpiredKey() {
        UUID id = UUID.randomUUID();
        ApiKeyEntity k = new ApiKeyEntity();
        k.setRevoked(false);
        k.setExpiresAt(OffsetDateTime.now().minusSeconds(1));
        when(apiKeyStore.findById(id)).thenReturn(Optional.of(k));
        assertFalse(service.check(id));
    }

    @Test
    void check_returnsTrue_forValidKeyWithExpiry() {
        UUID id = UUID.randomUUID();
        ApiKeyEntity k = new ApiKeyEntity();
        k.setRevoked(false);
        k.setExpiresAt(OffsetDateTime.now().plusDays(10));
        when(apiKeyStore.findById(id)).thenReturn(Optional.of(k));
        assertTrue(service.check(id));
    }

    @Test
    void check_returnsTrue_forKeyWithNoExpiry() {
        UUID id = UUID.randomUUID();
        ApiKeyEntity k = new ApiKeyEntity();
        k.setRevoked(false);
        k.setExpiresAt(null);
        when(apiKeyStore.findById(id)).thenReturn(Optional.of(k));
        assertTrue(service.check(id));
    }

    // --- listByUser ---

    @Test
    void listByUser_throwsForNull() {
        assertThrows(NullPointerException.class, () -> service.listByUser(null));
    }

    @Test
    void listByUser_delegatesToStore() {
        UUID userId = UUID.randomUUID();
        ApiKeyEntity k = new ApiKeyEntity();
        when(apiKeyStore.findByUser(userId)).thenReturn(List.of(k));

        List<ApiKeyEntity> result = service.listByUser(userId);
        assertEquals(1, result.size());
        verify(apiKeyStore).findByUser(userId);
    }

    // --- getApiKey ---

    @Test
    void getApiKey_throwsForNull() {
        assertThrows(NullPointerException.class, () -> service.getApiKey(null));
    }

    @Test
    void getApiKey_returnsKey() {
        UUID id = UUID.randomUUID();
        ApiKeyEntity k = new ApiKeyEntity();
        when(apiKeyStore.findById(id)).thenReturn(Optional.of(k));
        assertEquals(k, service.getApiKey(id));
    }

    @Test
    void getApiKey_throwsWhenNotFound() {
        UUID id = UUID.randomUUID();
        when(apiKeyStore.findById(id)).thenReturn(Optional.empty());
        assertThrows(NoSuchElementException.class, () -> service.getApiKey(id));
    }

    // --- revoke ---

    @Test
    void revoke_marksKeyAsRevokedWithTimestamp() {
        UUID keyId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();

        ApiKeyEntity k = new ApiKeyEntity();
        k.setId(keyId);
        k.setUserId(userId);
        k.setRevoked(false);

        when(apiKeyStore.findById(keyId)).thenReturn(Optional.of(k));
        when(apiKeyStore.update(k)).thenReturn(k);

        service.revoke(keyId, userId);

        assertTrue(k.getRevoked());
        assertNotNull(k.getRevokedAt());
        verify(apiKeyStore).update(k);
    }

    @Test
    void revoke_isIdempotent_whenAlreadyRevoked() {
        UUID keyId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();

        ApiKeyEntity k = new ApiKeyEntity();
        k.setId(keyId);
        k.setUserId(userId);
        k.setRevoked(true);

        when(apiKeyStore.findById(keyId)).thenReturn(Optional.of(k));

        service.revoke(keyId, userId);

        verify(apiKeyStore, never()).update(any());
    }

    @Test
    void revoke_throwsSecurityException_forWrongUser() {
        UUID keyId = UUID.randomUUID();
        UUID ownerId = UUID.randomUUID();
        UUID otherId = UUID.randomUUID();

        ApiKeyEntity k = new ApiKeyEntity();
        k.setId(keyId);
        k.setUserId(ownerId);
        k.setRevoked(false);

        when(apiKeyStore.findById(keyId)).thenReturn(Optional.of(k));

        assertThrows(SecurityException.class, () -> service.revoke(keyId, otherId));
    }

    @Test
    void revoke_throwsForNullKeyId() {
        assertThrows(NullPointerException.class,
                () -> service.revoke(null, UUID.randomUUID()));
    }

    @Test
    void revoke_throwsForNullRequestingUserId() {
        assertThrows(NullPointerException.class,
                () -> service.revoke(UUID.randomUUID(), null));
    }

    // --- revokeAllForUser ---

    @Test
    void revokeAllForUser_throwsForNull() {
        assertThrows(NullPointerException.class, () -> service.revokeAllForUser(null));
    }

    @Test
    void revokeAllForUser_revokesOnlyActiveKeys() {
        UUID userId = UUID.randomUUID();

        ApiKeyEntity active = new ApiKeyEntity();
        active.setId(UUID.randomUUID());
        active.setUserId(userId);
        active.setRevoked(false);

        ApiKeyEntity alreadyRevoked = new ApiKeyEntity();
        alreadyRevoked.setId(UUID.randomUUID());
        alreadyRevoked.setUserId(userId);
        alreadyRevoked.setRevoked(true);

        when(apiKeyStore.findByUser(userId)).thenReturn(List.of(active, alreadyRevoked));
        when(apiKeyStore.update(active)).thenReturn(active);

        service.revokeAllForUser(userId);

        assertTrue(active.getRevoked());
        assertNotNull(active.getRevokedAt());
        verify(apiKeyStore, times(1)).update(any());
    }

    @Test
    void revokeAllForUser_doesNothingWhenNoKeys() {
        UUID userId = UUID.randomUUID();
        when(apiKeyStore.findByUser(userId)).thenReturn(List.of());

        service.revokeAllForUser(userId);

        verify(apiKeyStore, never()).update(any());
    }

    // --- create (pre-JWT-signing validations only) ---
    // Note: the JWT signing step (Jwt.sign()) requires Quarkus CDI context and must be
    // covered by an integration test. The tests below cover all validations before that.

    @Test
    void create_throwsForNullUserId() {
        assertThrows(NullPointerException.class,
                () -> service.create(null, "key", Duration.ofDays(30)));
    }

    @Test
    void create_throwsForZeroLifetime() {
        assertThrows(IllegalArgumentException.class,
                () -> service.create(UUID.randomUUID(), "key", Duration.ZERO));
    }

    @Test
    void create_throwsForNegativeLifetime() {
        assertThrows(IllegalArgumentException.class,
                () -> service.create(UUID.randomUUID(), "key", Duration.ofDays(-5)));
    }

    @Test
    void create_throwsWhenNoLifetimeAndNoDefaultTtl() {
        when(runtimeConfig.apiToken().defaultTtl()).thenReturn(Optional.empty());
        assertThrows(IllegalArgumentException.class,
                () -> service.create(UUID.randomUUID(), "key", null));
    }

    @Test
    void create_throwsWhenUserNotFound() {
        UUID userId = UUID.randomUUID();
        when(userService.findById(userId)).thenThrow(new NoSuchElementException("no user"));

        assertThrows(NoSuchElementException.class,
                () -> service.create(userId, "key", Duration.ofDays(30)));
    }

    @Test
    void create_throwsForBlockedUser() {
        UUID userId = UUID.randomUUID();
        UserEntity blocked = new UserEntity();
        blocked.setState(UserStateEnum.BLOCKED);
        when(userService.findById(userId)).thenReturn(blocked);

        assertThrows(IllegalStateException.class,
                () -> service.create(userId, "key", Duration.ofDays(30)));
    }

    // --- recordUsage ---

    @Test
    void recordUsage_doesNothing_forNull() {
        service.recordUsage(null);
        verifyNoInteractions(apiKeyStore);
    }

    @Test
    void recordUsage_doesNothing_whenTrackingDisabled() {
        when(runtimeConfig.apiToken().trackUsage()).thenReturn(false);
        service.recordUsage(UUID.randomUUID());
        verifyNoInteractions(apiKeyStore);
    }

    @Test
    void recordUsage_updatesLastUsedAt_whenNeverUsed() {
        UUID id = UUID.randomUUID();
        ApiKeyEntity k = new ApiKeyEntity();
        k.setId(id);
        k.setLastUsedAt(null);

        when(runtimeConfig.apiToken().trackUsage()).thenReturn(true);
        when(runtimeConfig.apiToken().usageUpdateThrottle()).thenReturn(Duration.ofMinutes(1));
        when(apiKeyStore.findById(id)).thenReturn(Optional.of(k));

        service.recordUsage(id);

        assertNotNull(k.getLastUsedAt());
        verify(apiKeyStore).update(k);
    }

    @Test
    void recordUsage_skipsUpdate_withinThrottleWindow() {
        UUID id = UUID.randomUUID();
        ApiKeyEntity k = new ApiKeyEntity();
        k.setId(id);
        k.setLastUsedAt(OffsetDateTime.now());

        when(runtimeConfig.apiToken().trackUsage()).thenReturn(true);
        when(runtimeConfig.apiToken().usageUpdateThrottle()).thenReturn(Duration.ofMinutes(5));
        when(apiKeyStore.findById(id)).thenReturn(Optional.of(k));

        service.recordUsage(id);

        verify(apiKeyStore, never()).update(any());
    }
}
