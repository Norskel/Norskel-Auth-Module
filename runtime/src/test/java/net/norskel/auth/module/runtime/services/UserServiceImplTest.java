package net.norskel.auth.module.runtime.services;

import net.norskel.auth.module.runtime.config.AuthRuntimeConfig;
import net.norskel.auth.module.runtime.entities.UserEntity;
import net.norskel.auth.module.runtime.enums.UserStateEnum;
import net.norskel.auth.module.runtime.enums.UserTypeEnum;
import net.norskel.auth.module.runtime.exceptions.AuthConflictException;
import net.norskel.auth.module.runtime.exceptions.AuthNotFoundException;
import net.norskel.auth.module.runtime.exceptions.AuthValidationException;
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
import java.util.Set;
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
        lenient().when(config.user().autoCreateOnOidc()).thenReturn(true);
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
    void upsertFromOidc_rejectsUnknownUser_whenAutoCreateDisabled() {
        when(config.user().autoCreateOnOidc()).thenReturn(false);
        when(userStore.findByOidcId("sub-new")).thenReturn(Optional.empty());

        assertThrows(NoSuchElementException.class,
                () -> service.upsertFromOidc("sub-new", "mail@test.com", "Alice"));
        verify(userStore, never()).persist(any());
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

    /**
     * The provider can rename a person at any time, so a returning login must be
     * guarded exactly like a first one — otherwise a person can be renamed onto a
     * service's username and shadow it.
     */
    @Test
    void upsertFromOidc_rejectsRenameOntoAServiceUsername() {
        UserEntity existing = new UserEntity();
        existing.setId(UUID.randomUUID());
        existing.setOidcId("sub-4");
        existing.setEmail("dave@test.com");
        existing.setUsername("OldName");

        UserEntity svc = new UserEntity();
        svc.setId(UUID.randomUUID());
        svc.setUsername("report-collector");
        svc.setType(UserTypeEnum.SERVICE);

        when(userStore.findByOidcId("sub-4")).thenReturn(Optional.of(existing));
        when(userStore.findAll()).thenReturn(List.of(existing, svc));

        assertThrows(AuthConflictException.class,
                () -> service.upsertFromOidc("sub-4", "dave@test.com", "report-collector"));
        verify(userStore, never()).update(any());
        assertEquals("OldName", existing.getUsername());
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

    @Test
    void upsertFromOidc_storesAvatarOnCreate() {
        when(userStore.findByOidcId("sub-5")).thenReturn(Optional.empty());
        when(userStore.persist(any())).thenAnswer(inv -> inv.getArgument(0));

        UserEntity result = service.upsertFromOidc(
                "sub-5", "mail@test.com", "Erin", "https://idp/erin.png");

        assertEquals("https://idp/erin.png", result.getAvatarUrl());
    }

    @Test
    void upsertFromOidc_syncsAvatarWhenChanged() {
        UserEntity existing = new UserEntity();
        existing.setId(UUID.randomUUID());
        existing.setOidcId("sub-6");
        existing.setEmail("frank@test.com");
        existing.setUsername("Frank");
        existing.setAvatarUrl("https://idp/old.png");
        when(userStore.findByOidcId("sub-6")).thenReturn(Optional.of(existing));
        when(userStore.update(existing)).thenReturn(existing);

        service.upsertFromOidc("sub-6", "frank@test.com", "Frank", "https://idp/new.png");

        verify(userStore).update(existing);
        assertEquals("https://idp/new.png", existing.getAvatarUrl());
    }

    /**
     * A provider that stops sending the picture claim must not wipe the avatar we
     * already have — same rule as the email.
     */
    @Test
    void upsertFromOidc_keepsAvatarWhenClaimAbsent() {
        UserEntity existing = new UserEntity();
        existing.setId(UUID.randomUUID());
        existing.setOidcId("sub-7");
        existing.setEmail("gina@test.com");
        existing.setUsername("Gina");
        existing.setAvatarUrl("https://idp/gina.png");
        when(userStore.findByOidcId("sub-7")).thenReturn(Optional.of(existing));

        service.upsertFromOidc("sub-7", "gina@test.com", "Gina", null);

        verify(userStore, never()).update(any());
        assertEquals("https://idp/gina.png", existing.getAvatarUrl());
    }

    // --- upsertFromOidc: rôle piloté par le SSO ---

    @Test
    void upsertFromOidc_forcesTheGovernedRoleGrantedBySso() {
        when(config.user().dbRoleFromSso()).thenReturn(Optional.of(List.of("admin", "manager")));
        UserEntity existing = oidcUser("sub-10", "user");
        when(userStore.findByOidcId("sub-10")).thenReturn(Optional.of(existing));
        when(userStore.update(existing)).thenReturn(existing);

        service.upsertFromOidc("sub-10", "sub-10@test.com", "sub-10", null, Set.of("manager"));

        verify(userStore).update(existing);
        assertEquals("manager", existing.getRole());
    }

    /**
     * The row holds a single role, so when the provider grants several the winner has
     * to come from the configured order rather than from the order of the claims.
     */
    @Test
    void upsertFromOidc_prefersTheFirstConfiguredRole_whenSsoGrantsSeveral() {
        when(config.user().dbRoleFromSso()).thenReturn(Optional.of(List.of("admin", "manager")));
        UserEntity existing = oidcUser("sub-11", "user");
        when(userStore.findByOidcId("sub-11")).thenReturn(Optional.of(existing));
        when(userStore.update(existing)).thenReturn(existing);

        service.upsertFromOidc("sub-11", "sub-11@test.com", "sub-11", null,
                Set.of("manager", "admin"));

        assertEquals("admin", existing.getRole());
    }

    /** A privilege revoked at the IdP must not survive in our table. */
    @Test
    void upsertFromOidc_dropsToDefaultRole_whenSsoNoLongerGrantsAGovernedRole() {
        when(config.user().dbRoleFromSso()).thenReturn(Optional.of(List.of("admin", "manager")));
        UserEntity existing = oidcUser("sub-12", "admin");
        when(userStore.findByOidcId("sub-12")).thenReturn(Optional.of(existing));
        when(userStore.update(existing)).thenReturn(existing);

        service.upsertFromOidc("sub-12", "sub-12@test.com", "sub-12", null, Set.of("some-other-role"));

        verify(userStore).update(existing);
        assertEquals("user", existing.getRole());
    }

    /**
     * A role outside the governed list was granted by hand: the provider has no say
     * over it, and a login must not silently take it away.
     */
    @Test
    void upsertFromOidc_leavesAnUngovernedRoleAlone() {
        when(config.user().dbRoleFromSso()).thenReturn(Optional.of(List.of("admin")));
        UserEntity existing = oidcUser("sub-13", "auditor");
        when(userStore.findByOidcId("sub-13")).thenReturn(Optional.of(existing));

        service.upsertFromOidc("sub-13", "sub-13@test.com", "sub-13", null, Set.of());

        verify(userStore, never()).update(any());
        assertEquals("auditor", existing.getRole());
    }

    @Test
    void upsertFromOidc_appliesTheSsoRoleOnCreate() {
        when(config.user().dbRoleFromSso()).thenReturn(Optional.of(List.of("admin")));
        when(userStore.findByOidcId("sub-14")).thenReturn(Optional.empty());
        when(userStore.persist(any())).thenAnswer(inv -> inv.getArgument(0));

        UserEntity result = service.upsertFromOidc("sub-14", "sub-14@test.com", "sub-14", null,
                Set.of("admin"));

        assertEquals("admin", result.getRole());
    }

    /** Unconfigured, the stored role stays exactly as it was — the previous behaviour. */
    @Test
    void upsertFromOidc_ignoresSsoRoles_whenNoRoleIsGoverned() {
        UserEntity existing = oidcUser("sub-15", "user");
        when(userStore.findByOidcId("sub-15")).thenReturn(Optional.of(existing));

        service.upsertFromOidc("sub-15", "sub-15@test.com", "sub-15", null, Set.of("admin"));

        verify(userStore, never()).update(any());
        assertEquals("user", existing.getRole());
    }

    private static UserEntity oidcUser(String oidcId, String role) {
        UserEntity u = new UserEntity();
        u.setId(UUID.randomUUID());
        u.setOidcId(oidcId);
        u.setEmail(oidcId + "@test.com");
        u.setUsername(oidcId);
        u.setRole(role);
        return u;
    }

    // --- create ---

    @Test
    void create_throwsForNullEntity() {
        assertThrows(NullPointerException.class, () -> service.create(null));
    }

    /** A minimally valid person; create() now enforces the per-type field rules. */
    private static UserEntity humanUser() {
        UserEntity u = new UserEntity();
        u.setUsername("someone");
        u.setEmail("someone@test.com");
        u.setOidcId("oidc-someone");
        return u;
    }

    @Test
    void create_assignsIdAndCreatedAtWhenAbsent() {
        when(userStore.persist(any())).thenAnswer(inv -> inv.getArgument(0));

        UserEntity result = service.create(humanUser());

        assertNotNull(result.getId());
        assertNotNull(result.getCreatedAt());
        assertEquals(UserTypeEnum.HUMAN, result.getType());
        assertEquals(UserStateEnum.ACTIVE, result.getState());
    }

    @Test
    void create_keepsExistingId() {
        UUID id = UUID.randomUUID();
        UserEntity u = humanUser();
        u.setId(id);
        when(userStore.persist(any())).thenAnswer(inv -> inv.getArgument(0));

        service.create(u);

        assertEquals(id, u.getId());
    }

    @Test
    void create_throwsOnDuplicateOidcId() {
        UserEntity u = humanUser();
        u.setOidcId("dup-oidc");
        when(userStore.findByOidcId("dup-oidc")).thenReturn(Optional.of(new UserEntity()));

        assertThrows(IllegalStateException.class, () -> service.create(u));
    }

    @Test
    void create_throwsOnDuplicateUsername() {
        UserEntity u = humanUser();
        u.setUsername("dup-user");
        when(userStore.findByOidcId(any())).thenReturn(Optional.empty());
        UserEntity other = humanUser();
        other.setId(UUID.randomUUID());
        other.setUsername("dup-user");
        when(userStore.findAll()).thenReturn(List.of(other));

        assertThrows(IllegalStateException.class, () -> service.create(u));
    }

    // --- per-type validation ---

    @Test
    void create_requiresEmailAndOidcIdForAHuman() {
        UserEntity noEmail = humanUser();
        noEmail.setEmail(null);
        assertThrows(AuthValidationException.class, () -> service.create(noEmail));

        UserEntity noOidc = humanUser();
        noOidc.setOidcId(null);
        assertThrows(AuthValidationException.class, () -> service.create(noOidc));
    }

    @Test
    void create_rejectsAServiceCarryingHumanOnlyFields() {
        UserEntity withOidc = new UserEntity();
        withOidc.setUsername("svc");
        withOidc.setRole("billing");
        withOidc.setType(UserTypeEnum.SERVICE);
        withOidc.setOidcId("should-not-be-here");
        assertThrows(AuthValidationException.class, () -> service.create(withOidc));

        UserEntity withEmail = new UserEntity();
        withEmail.setUsername("svc");
        withEmail.setRole("billing");
        withEmail.setType(UserTypeEnum.SERVICE);
        withEmail.setEmail("svc@test.com");
        assertThrows(AuthValidationException.class, () -> service.create(withEmail));
    }

    @Test
    void create_requiresARoleForAService() {
        UserEntity svc = new UserEntity();
        svc.setUsername("svc");
        svc.setType(UserTypeEnum.SERVICE);
        assertThrows(AuthValidationException.class, () -> service.create(svc));
    }

    @Test
    void create_acceptsAValidService() {
        UserEntity svc = new UserEntity();
        svc.setUsername("billing-worker");
        svc.setRole("billing");
        svc.setType(UserTypeEnum.SERVICE);
        when(userStore.persist(any())).thenAnswer(inv -> inv.getArgument(0));

        UserEntity created = service.create(svc);

        assertEquals(UserTypeEnum.SERVICE, created.getType());
        assertEquals(UserStateEnum.ACTIVE, created.getState());
        assertNull(created.getOidcId());
    }

    // --- findOrCreateService ---

    @Test
    void findOrCreateService_createsWhenAbsent() {
        when(userStore.findByUsername("svc")).thenReturn(Optional.empty());
        when(userStore.persist(any())).thenAnswer(inv -> inv.getArgument(0));

        UserEntity svc = service.findOrCreateService("svc", "billing");

        assertEquals(UserTypeEnum.SERVICE, svc.getType());
        assertEquals("billing", svc.getRole());
    }

    @Test
    void findOrCreateService_recordsWhoCreatedTheService() {
        UUID admin = UUID.randomUUID();
        when(userStore.findByUsername("svc")).thenReturn(Optional.empty());
        when(userStore.persist(any())).thenAnswer(inv -> inv.getArgument(0));

        UserEntity svc = service.findOrCreateService("svc", "billing", admin);

        // Without this, a departing admin's leftover services are untraceable.
        assertEquals(admin, svc.getCreatedBy());
    }

    @Test
    void findOrCreateService_reusesTheExistingService() {
        UserEntity existing = UserEntity.builder()
                .id(UUID.randomUUID()).username("svc").role("billing")
                .type(UserTypeEnum.SERVICE).build();
        when(userStore.findByUsername("svc")).thenReturn(Optional.of(existing));

        assertEquals(existing, service.findOrCreateService("svc", "billing"));
        verify(userStore, never()).persist(any());
    }

    @Test
    void findOrCreateService_refusesToChangeTheRoleOfAnExistingService() {
        // Otherwise minting a key would silently escalate the service.
        UserEntity existing = UserEntity.builder()
                .id(UUID.randomUUID()).username("svc").role("billing")
                .type(UserTypeEnum.SERVICE).build();
        when(userStore.findByUsername("svc")).thenReturn(Optional.of(existing));

        assertThrows(AuthConflictException.class,
                () -> service.findOrCreateService("svc", "admin"));
    }

    @Test
    void findOrCreateService_refusesToHijackAHumanUsername() {
        UserEntity human = UserEntity.builder()
                .id(UUID.randomUUID()).username("alice").role("user")
                .type(UserTypeEnum.HUMAN).build();
        when(userStore.findByUsername("alice")).thenReturn(Optional.of(human));

        assertThrows(AuthConflictException.class,
                () -> service.findOrCreateService("alice", "billing"));
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
        UserEntity u = humanUser();
        u.setId(UUID.randomUUID());
        when(userStore.findAll()).thenReturn(List.of(u));
        when(userStore.update(u)).thenReturn(u);

        service.update(u);

        verify(userStore).update(u);
    }

    @Test
    void update_rejectsEmailOnAService() {
        UserEntity svc = new UserEntity();
        svc.setId(UUID.randomUUID());
        svc.setUsername("report-collector");
        svc.setRole("collector");
        svc.setType(UserTypeEnum.SERVICE);
        svc.setEmail("leaked@test.com");

        assertThrows(AuthValidationException.class, () -> service.update(svc));
        verify(userStore, never()).update(any());
    }

    @Test
    void update_rejectsRenameOntoAnotherUsername() {
        UserEntity svc = new UserEntity();
        svc.setId(UUID.randomUUID());
        svc.setUsername("report-collector");
        svc.setRole("collector");
        svc.setType(UserTypeEnum.SERVICE);

        // The person has already been renamed in place, as an in-place store
        // would have it by the time update() runs.
        UserEntity person = humanUser();
        person.setId(UUID.randomUUID());
        person.setUsername("report-collector");
        when(userStore.findAll()).thenReturn(List.of(person, svc));

        assertThrows(AuthConflictException.class, () -> service.update(person));
        verify(userStore, never()).update(any());
    }

    @Test
    void update_rejectsBlankRoleOnAService() {
        UserEntity svc = new UserEntity();
        svc.setId(UUID.randomUUID());
        svc.setUsername("report-collector");
        svc.setType(UserTypeEnum.SERVICE);
        svc.setRole("");

        assertThrows(AuthValidationException.class, () -> service.update(svc));
        verify(userStore, never()).update(any());
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
    void deleteById_throwsForNullId() {
        assertThrows(NullPointerException.class, () -> service.deleteById(null));
    }

    @Test
    void deleteById_delegatesToStore() {
        UUID id = UUID.randomUUID();
        when(userStore.deleteById(id)).thenReturn(true);

        service.deleteById(id);

        verify(userStore).deleteById(id);
    }

    @Test
    void deleteById_throwsNotFound_whenStoreRemovedNothing() {
        UUID id = UUID.randomUUID();
        when(userStore.deleteById(id)).thenReturn(false);

        assertThrows(AuthNotFoundException.class, () -> service.deleteById(id));
    }
}
