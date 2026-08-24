package net.norskel.auth.module.runtime.services;

import net.norskel.auth.module.runtime.config.AuthBuildTimeConfig;
import net.norskel.auth.module.runtime.config.AuthRuntimeConfig;
import net.norskel.auth.module.runtime.entities.ApiKeyEntity;
import net.norskel.auth.module.runtime.entities.UserEntity;
import net.norskel.auth.module.runtime.enums.UserStateEnum;
import net.norskel.auth.module.runtime.enums.UserTypeEnum;
import net.norskel.auth.module.runtime.exceptions.AuthConflictException;
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
import static org.mockito.ArgumentMatchers.eq;
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

    // --- service keys (pre-JWT-signing validations only, as above) ---

    // --- service keys: now a thin composition over create() ---

    @Test
    void createServiceKey_delegatesToTheServiceLookupThenTheOrdinaryCreateFlow() {
        // Ownership of the issued key is asserted end-to-end in
        // AuthModuleIntegrationTest, which has real signing keys; this test only
        // pins the delegation, since create() signs a token.
        UUID svcId = UUID.randomUUID();
        UserEntity svc = UserEntity.builder()
                .id(svcId).username("billing-worker").role("billing")
                .type(UserTypeEnum.SERVICE).state(UserStateEnum.BLOCKED)
                .build();
        when(userService.findOrCreateService(eq("billing-worker"), eq("billing"), any()))
                .thenReturn(svc);
        when(userService.findById(svcId)).thenReturn(svc);

        // Blocked service => create() refuses before reaching the signer, which
        // also shows the service goes through the same guard as a person.
        assertThrows(AuthConflictException.class, () -> service
                .createServiceKey("billing-worker", "nightly", "billing", Duration.ofDays(1)));
        verify(userService).findOrCreateService(eq("billing-worker"), eq("billing"), any());
        verify(apiKeyStore, never()).persist(any());
    }

    @Test
    void createServiceKey_propagatesConflictFromTheServiceLookup() {
        when(userService.findOrCreateService(eq("taken"), eq("billing"), any()))
                .thenThrow(new IllegalStateException("already exists with role x"));

        assertThrows(IllegalStateException.class, () -> service
                .createServiceKey("taken", "nightly", "billing", Duration.ofDays(1)));
        verify(apiKeyStore, never()).persist(any());
    }

    @Test
    void listServiceKeys_collectsKeysOfEveryServiceUser() {
        UUID a = UUID.randomUUID();
        UUID b = UUID.randomUUID();
        when(userService.findByType(UserTypeEnum.SERVICE)).thenReturn(List.of(
                UserEntity.builder().id(a).type(UserTypeEnum.SERVICE).build(),
                UserEntity.builder().id(b).type(UserTypeEnum.SERVICE).build()));
        ApiKeyEntity k1 = new ApiKeyEntity();
        ApiKeyEntity k2 = new ApiKeyEntity();
        when(apiKeyStore.findByUser(a)).thenReturn(List.of(k1));
        when(apiKeyStore.findByUser(b)).thenReturn(List.of(k2));

        assertEquals(List.of(k1, k2), service.listServiceKeys());
    }
}
