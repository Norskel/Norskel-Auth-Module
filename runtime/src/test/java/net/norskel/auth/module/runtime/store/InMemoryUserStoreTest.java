package net.norskel.auth.module.runtime.store;

import net.norskel.auth.module.runtime.entities.UserEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class InMemoryUserStoreTest {

    private InMemoryUserStore store;

    @BeforeEach
    void setUp() {
        store = new InMemoryUserStore();
    }

    @Test
    void persist_assignsIdWhenNull() {
        UserEntity u = new UserEntity();
        assertNull(u.getId());
        store.persist(u);
        assertNotNull(u.getId());
    }

    @Test
    void persist_keepsExistingId() {
        UUID id = UUID.randomUUID();
        UserEntity u = new UserEntity();
        u.setId(id);
        store.persist(u);
        assertEquals(id, u.getId());
    }

    @Test
    void persist_throwsOnDuplicateId() {
        UUID id = UUID.randomUUID();
        UserEntity u = new UserEntity();
        u.setId(id);
        store.persist(u);

        UserEntity dup = new UserEntity();
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
    void findById_returnsUser_whenPresent() {
        UserEntity u = new UserEntity();
        store.persist(u);
        assertTrue(store.findById(u.getId()).isPresent());
    }

    @Test
    void findByOidcId_returnsEmpty_forNull() {
        assertTrue(store.findByOidcId(null).isEmpty());
    }

    @Test
    void findByOidcId_returnsEmpty_whenNotFound() {
        assertTrue(store.findByOidcId("unknown-sub").isEmpty());
    }

    @Test
    void findByOidcId_findsMatchingUser() {
        UserEntity u = new UserEntity();
        u.setOidcId("sub-abc");
        store.persist(u);
        assertTrue(store.findByOidcId("sub-abc").isPresent());
        assertEquals("sub-abc", store.findByOidcId("sub-abc").get().getOidcId());
    }

    @Test
    void findByUsername_returnsEmpty_forNull() {
        assertTrue(store.findByUsername(null).isEmpty());
    }

    @Test
    void findByUsername_returnsEmpty_whenNotFound() {
        assertTrue(store.findByUsername("unknown").isEmpty());
    }

    @Test
    void findByUsername_findsMatchingUser() {
        UserEntity u = new UserEntity();
        u.setUsername("alice");
        store.persist(u);
        assertTrue(store.findByUsername("alice").isPresent());
    }

    @Test
    void findAll_returnsEmptyList_initially() {
        assertTrue(store.findAll().isEmpty());
    }

    @Test
    void findAll_returnsAllPersisted() {
        store.persist(new UserEntity());
        store.persist(new UserEntity());
        assertEquals(2, store.findAll().size());
    }

    @Test
    void findAll_returnsCopy_notLiveReference() {
        store.persist(new UserEntity());
        List<UserEntity> first = store.findAll();
        store.persist(new UserEntity());
        assertEquals(1, first.size(), "findAll should return a snapshot, not a live view");
    }

    @Test
    void update_replacesExisting() {
        UserEntity u = new UserEntity();
        u.setEmail("old@example.com");
        store.persist(u);

        u.setEmail("new@example.com");
        store.update(u);

        assertEquals("new@example.com", store.findById(u.getId()).get().getEmail());
    }

    @Test
    void update_throwsWhenNotFound() {
        UserEntity u = new UserEntity();
        u.setId(UUID.randomUUID());
        assertThrows(NoSuchElementException.class, () -> store.update(u));
    }

    @Test
    void update_throwsForNullEntity() {
        assertThrows(NullPointerException.class, () -> store.update(null));
    }

    @Test
    void update_throwsForNullId() {
        UserEntity u = new UserEntity();
        assertThrows(NullPointerException.class, () -> store.update(u));
    }
}
