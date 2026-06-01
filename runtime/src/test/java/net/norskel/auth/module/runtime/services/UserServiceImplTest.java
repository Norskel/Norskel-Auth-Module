package net.norskel.auth.module.runtime.services;

import net.norskel.auth.module.runtime.config.AuthRuntimeConfig;
import net.norskel.auth.module.runtime.entities.UserEntity;
import net.norskel.auth.module.runtime.enums.UserStateEnum;
import net.norskel.auth.module.runtime.spi.UserStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceImplTest {

    @Mock
    UserStore userStore;

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    AuthRuntimeConfig config;

    @InjectMocks
    UserServiceImpl service;

    @BeforeEach
    void setUp() {
        lenient().when(config.user().defaultRole()).thenReturn("user");
    }

    // --- findAll ---

    @Test
    void findAll_delegatesToStore() {
        UserEntity u = new UserEntity();
        when(userStore.findAll()).thenReturn(List.of(u));
        assertEquals(1, service.findAll().size());
        verify(userStore).findAll();
    }

    // --- upsertFromOidc ---

    @Test
    void upsertFromOidc_throwsForNullSubject() {
        assertThrows(NullPointerException.class,
                () -> service.upsertFromOidc(null, "email@test.com", "Alice"));
    }

    @Test
    void upsertFromOidc_createsNewUser_whenNotFound() {
        when(userStore.findByOidcId("sub-1")).thenReturn(Optional.empty());
        when(userStore.persist(any())).thenAnswer(inv -> inv.getArgument(0));

        UserEntity result = service.upsertFromOidc("sub-1", "mail@test.com", "Alice");

        verify(userStore).persist(any());
        assertNotNull(result.getId());
        assertEquals("sub-1", result.getOidcId());
        assertEquals("mail@test.com", result.getEmail());
        assertEquals("user", result.getRole());
    }

    @Test
    void upsertFromOidc_syncsEmailWhenChanged() {
        UserEntity existing = new UserEntity();
        existing.setId(UUID.randomUUID());
        existing.setOidcId("sub-2");
        existing.setEmail("old@test.com");
        existing.setUsername("Bob");
        when(userStore.findByOidcId("sub-2")).thenReturn(Optional.of(existing));
        when(userStore.update(existing)).thenReturn(existing);

        service.upsertFromOidc("sub-2", "new@test.com", "Bob");

        verify(userStore).update(existing);
        assertEquals("new@test.com", existing.getEmail());
    }

    @Test
    void upsertFromOidc_syncsUsernameWhenChanged() {
        UserEntity existing = new UserEntity();
        existing.setId(UUID.randomUUID());
        existing.setOidcId("sub-3");
        existing.setEmail("carol@test.com");
        existing.setUsername("OldName");
        when(userStore.findByOidcId("sub-3")).thenReturn(Optional.of(existing));
        when(userStore.update(existing)).thenReturn(existing);

        service.upsertFromOidc("sub-3", "carol@test.com", "NewName");

        verify(userStore).update(existing);
        assertEquals("NewName", existing.getUsername());
    }

    @Test
    void upsertFromOidc_doesNotUpdateWhenNothingChanged() {
        UserEntity existing = new UserEntity();
        existing.setId(UUID.randomUUID());
        existing.setOidcId("sub-4");
        existing.setEmail("same@test.com");
        existing.setUsername("Same");
        when(userStore.findByOidcId("sub-4")).thenReturn(Optional.of(existing));

        service.upsertFromOidc("sub-4", "same@test.com", "Same");

        verify(userStore, never()).update(any());
    }

    // --- create ---

    @Test
    void create_throwsForNullEntity() {
        assertThrows(NullPointerException.class, () -> service.create(null));
    }

    @Test
    void create_assignsIdAndCreatedAtWhenAbsent() {
        UserEntity u = new UserEntity();
        // oidcId and username are null → uniqueness checks are skipped, only persist is called
        when(userStore.persist(any())).thenAnswer(inv -> inv.getArgument(0));

        UserEntity result = service.create(u);

        assertNotNull(result.getId());
        assertNotNull(result.getCreatedAt());
    }

    @Test
    void create_keepsExistingId() {
        UUID id = UUID.randomUUID();
        UserEntity u = new UserEntity();
        u.setId(id);
        // oidcId and username are null → uniqueness checks are skipped
        when(userStore.persist(any())).thenAnswer(inv -> inv.getArgument(0));

        service.create(u);

        assertEquals(id, u.getId());
    }

    @Test
    void create_throwsOnDuplicateOidcId() {
        UserEntity u = new UserEntity();
        u.setOidcId("dup-oidc");
        when(userStore.findByOidcId("dup-oidc")).thenReturn(Optional.of(new UserEntity()));

        assertThrows(IllegalStateException.class, () -> service.create(u));
    }

    @Test
    void create_throwsOnDuplicateUsername() {
        UserEntity u = new UserEntity();
        u.setUsername("dup-user");
        // oidcId is null → findByOidcId is skipped; only findByUsername is called
        when(userStore.findByUsername("dup-user")).thenReturn(Optional.of(new UserEntity()));

        assertThrows(IllegalStateException.class, () -> service.create(u));
    }

    // --- findByOidcId ---

    @Test
    void findByOidcId_returnsUser() {
        UserEntity u = new UserEntity();
        when(userStore.findByOidcId("sub-x")).thenReturn(Optional.of(u));
        assertEquals(u, service.findByOidcId("sub-x"));
    }

    @Test
    void findByOidcId_throwsWhenNotFound() {
        when(userStore.findByOidcId("missing")).thenReturn(Optional.empty());
        assertThrows(NoSuchElementException.class, () -> service.findByOidcId("missing"));
    }

    // --- findByEmail ---

    @Test
    void findByEmail_throwsForNull() {
        assertThrows(NullPointerException.class, () -> service.findByEmail(null));
    }

    @Test
    void findByEmail_isCaseInsensitive() {
        UserEntity u = new UserEntity();
        u.setEmail("Alice@Example.Com");
        when(userStore.findAll()).thenReturn(List.of(u));

        assertEquals(u, service.findByEmail("alice@example.com"));
    }

    @Test
    void findByEmail_throwsWhenNotFound() {
        when(userStore.findAll()).thenReturn(List.of());
        assertThrows(NoSuchElementException.class, () -> service.findByEmail("nobody@test.com"));
    }

    // --- findByUsername ---

    @Test
    void findByUsername_returnsUser() {
        UserEntity u = new UserEntity();
        when(userStore.findByUsername("alice")).thenReturn(Optional.of(u));
        assertEquals(u, service.findByUsername("alice"));
    }

    @Test
    void findByUsername_throwsWhenNotFound() {
        when(userStore.findByUsername("unknown")).thenReturn(Optional.empty());
        assertThrows(NoSuchElementException.class, () -> service.findByUsername("unknown"));
    }

    // --- findById ---

    @Test
    void findById_returnsUser() {
        UUID id = UUID.randomUUID();
        UserEntity u = new UserEntity();
        when(userStore.findById(id)).thenReturn(Optional.of(u));
        assertEquals(u, service.findById(id));
    }

    @Test
    void findById_throwsWhenNotFound() {
        UUID id = UUID.randomUUID();
        when(userStore.findById(id)).thenReturn(Optional.empty());
        assertThrows(NoSuchElementException.class, () -> service.findById(id));
    }

    // --- update ---

    @Test
    void update_throwsForNullEntity() {
        assertThrows(NullPointerException.class, () -> service.update(null));
    }

    @Test
    void update_throwsForNullId() {
        assertThrows(NullPointerException.class, () -> service.update(new UserEntity()));
    }

    @Test
    void update_delegatesToStore() {
        UUID id = UUID.randomUUID();
        UserEntity u = new UserEntity();
        u.setId(id);
        when(userStore.update(u)).thenReturn(u);

        service.update(u);

        verify(userStore).update(u);
    }

    // --- banUser / unbanUser ---

    @Test
    void banUser_setsBlockedState() {
        UUID id = UUID.randomUUID();
        UserEntity u = new UserEntity();
        u.setId(id);
        u.setState(UserStateEnum.ACTIVE);
        when(userStore.findById(id)).thenReturn(Optional.of(u));
        when(userStore.update(u)).thenReturn(u);

        service.banUser(id);

        assertEquals(UserStateEnum.BLOCKED, u.getState());
        verify(userStore).update(u);
    }

    @Test
    void banUser_throwsWhenUserNotFound() {
        UUID id = UUID.randomUUID();
        when(userStore.findById(id)).thenReturn(Optional.empty());
        assertThrows(NoSuchElementException.class, () -> service.banUser(id));
    }

    @Test
    void unbanUser_setsActiveState() {
        UUID id = UUID.randomUUID();
        UserEntity u = new UserEntity();
        u.setId(id);
        u.setState(UserStateEnum.BLOCKED);
        when(userStore.findById(id)).thenReturn(Optional.of(u));
        when(userStore.update(u)).thenReturn(u);

        service.unbanUser(id);

        assertEquals(UserStateEnum.ACTIVE, u.getState());
        verify(userStore).update(u);
    }

    // --- updateLastLogin ---

    @Test
    void updateLastLogin_throwsForNullEntity() {
        assertThrows(NullPointerException.class, () -> service.updateLastLogin(null));
    }

    @Test
    void updateLastLogin_setsTimestampAndCallsUpdate() {
        UserEntity u = new UserEntity();
        u.setId(UUID.randomUUID());
        when(userStore.update(u)).thenReturn(u);

        service.updateLastLogin(u);

        assertNotNull(u.getLastLogin());
        verify(userStore).update(u);
    }

    // --- deleteById ---

    @Test
    void deleteById_throwsUnsupportedOperation() {
        assertThrows(UnsupportedOperationException.class,
                () -> service.deleteById(UUID.randomUUID()));
    }
}
