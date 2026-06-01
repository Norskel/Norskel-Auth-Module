package net.norskel.auth.module.runtime.store;

import net.norskel.auth.module.runtime.entities.ApiKeyEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class InMemoryApiKeyStoreTest {

    private InMemoryApiKeyStore store;

    @BeforeEach
    void setUp() {
        store = new InMemoryApiKeyStore();
    }

    @Test
    void persist_assignsIdWhenNull() {
        ApiKeyEntity k = new ApiKeyEntity();
        assertNull(k.getId());
        store.persist(k);
        assertNotNull(k.getId());
    }

    @Test
    void persist_keepsExistingId() {
        UUID id = UUID.randomUUID();
        ApiKeyEntity k = new ApiKeyEntity();
        k.setId(id);
        store.persist(k);
        assertEquals(id, k.getId());
    }

    @Test
    void persist_throwsOnDuplicateId() {
        UUID id = UUID.randomUUID();
        ApiKeyEntity k = new ApiKeyEntity();
        k.setId(id);
        store.persist(k);

        ApiKeyEntity dup = new ApiKeyEntity();
        dup.setId(id);
        assertThrows(IllegalStateException.class, () -> store.persist(dup));
    }

    @Test
    void persist_throwsForNullEntity() {
        assertThrows(NullPointerException.class, () -> store.persist(null));
    }

    @Test
    void findById_returnsEmpty_whenMissing() {
        assertTrue(store.findById(UUID.randomUUID()).isEmpty());
    }

    @Test
    void findById_returnsKey_whenPresent() {
        ApiKeyEntity k = new ApiKeyEntity();
        store.persist(k);
        assertTrue(store.findById(k.getId()).isPresent());
    }

    @Test
    void findByUser_returnsEmptyList_forNullUserId() {
        assertTrue(store.findByUser(null).isEmpty());
    }

    @Test
    void findByUser_returnsEmptyList_whenNoKeysForUser() {
        assertTrue(store.findByUser(UUID.randomUUID()).isEmpty());
    }

    @Test
    void findByUser_returnsOnlyKeysForGivenUser() {
        UUID userId1 = UUID.randomUUID();
        UUID userId2 = UUID.randomUUID();

        ApiKeyEntity k1 = new ApiKeyEntity();
        k1.setUserId(userId1);
        ApiKeyEntity k2 = new ApiKeyEntity();
        k2.setUserId(userId1);
        ApiKeyEntity k3 = new ApiKeyEntity();
        k3.setUserId(userId2);

        store.persist(k1);
        store.persist(k2);
        store.persist(k3);

        List<ApiKeyEntity> result = store.findByUser(userId1);
        assertEquals(2, result.size());
        assertTrue(result.stream().allMatch(k -> userId1.equals(k.getUserId())));
    }

    @Test
    void findByUser_doesNotReturnKeysOfOtherUsers() {
        UUID userId1 = UUID.randomUUID();
        UUID userId2 = UUID.randomUUID();

        ApiKeyEntity k = new ApiKeyEntity();
        k.setUserId(userId1);
        store.persist(k);

        assertTrue(store.findByUser(userId2).isEmpty());
    }

    @Test
    void update_replacesExisting() {
        ApiKeyEntity k = new ApiKeyEntity();
        k.setRevoked(false);
        store.persist(k);

        k.setRevoked(true);
        store.update(k);

        assertTrue(store.findById(k.getId()).get().getRevoked());
    }

    @Test
    void update_throwsWhenNotFound() {
        ApiKeyEntity k = new ApiKeyEntity();
        k.setId(UUID.randomUUID());
        assertThrows(NoSuchElementException.class, () -> store.update(k));
    }

    @Test
    void update_throwsForNullEntity() {
        assertThrows(NullPointerException.class, () -> store.update(null));
    }

    @Test
    void update_throwsForNullId() {
        ApiKeyEntity k = new ApiKeyEntity();
        assertThrows(NullPointerException.class, () -> store.update(k));
    }
}
