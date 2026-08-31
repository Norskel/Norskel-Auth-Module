package net.norskel.auth.module.runtime;

import io.quarkus.oidc.UserInfo;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import net.norskel.auth.module.runtime.config.AuthRuntimeConfig;
import net.norskel.auth.module.runtime.entities.UserEntity;
import net.norskel.auth.module.runtime.roles.ClaimRoleResolver;
import net.norskel.auth.module.runtime.enums.UserStateEnum;
import net.norskel.auth.module.runtime.spi.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OIDCSecurityIdentitySupplierTest {

    @Mock
    SecurityIdentity identity;

    @Mock
    UserService userService;

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    AuthRuntimeConfig config;

    @Mock
    ClaimRoleResolver claimRoleResolver;

    @InjectMocks
    OIDCSecurityIdentitySupplier supplier;

    @BeforeEach
    void setUp() {
        lenient().when(config.user().subjectClaim()).thenReturn("sub");
        lenient().when(config.user().emailClaims())
                .thenReturn(List.of("email", "preferred_username"));
        lenient().when(config.user().avatarClaims())
                .thenReturn(List.of("picture", "avatar_url"));
        lenient().when(config.user().rolesClaim()).thenReturn(Optional.empty());
        // No role-mapping rule by default, so the existing tests keep asserting what they did.
        lenient().when(claimRoleResolver.rolesFor(any(UserInfo.class))).thenReturn(Set.of());
    }

    @Test
    void get_throwsWhenUserInfoMissing() {
        doReturn(null).when(identity).getAttribute("userinfo");

        assertThrows(AuthenticationFailedException.class, () -> supplier.augment(identity));
        verify(userService, never()).upsertFromOidc(any(), any(), any(), any());
    }

    @Test
    void get_throwsWhenSubjectIsNull() {
        UserInfo userInfo = mock(UserInfo.class);
        when(userInfo.getString("sub")).thenReturn(null);
        doReturn(userInfo).when(identity).getAttribute("userinfo");

        assertThrows(AuthenticationFailedException.class, () -> supplier.augment(identity));
        verify(userService, never()).upsertFromOidc(any(), any(), any(), any());
    }

    @Test
    void get_throwsWhenSubjectIsBlank() {
        UserInfo userInfo = mock(UserInfo.class);
        when(userInfo.getString("sub")).thenReturn("   ");
        doReturn(userInfo).when(identity).getAttribute("userinfo");

        assertThrows(AuthenticationFailedException.class, () -> supplier.augment(identity));
        verify(userService, never()).upsertFromOidc(any(), any(), any(), any());
    }

    @Test
    void get_throwsWhenUserSyncFails() {
        UserInfo userInfo = mock(UserInfo.class);
        when(userInfo.getString("sub")).thenReturn("sub-x");
        when(userInfo.getString("email")).thenReturn("user@test.com");
        when(userInfo.getString("preferred_username")).thenReturn("testuser");
        doReturn(userInfo).when(identity).getAttribute("userinfo");
        when(userService.upsertFromOidc(any(), any(), any(), any()))
                .thenThrow(new RuntimeException("DB error"));

        assertThrows(AuthenticationFailedException.class, () -> supplier.augment(identity));
    }

    @Test
    void get_throwsWhenUserIsBlocked() {
        UserInfo userInfo = mock(UserInfo.class);
        when(userInfo.getString("sub")).thenReturn("sub-blocked");
        when(userInfo.getString("email")).thenReturn("blocked@test.com");
        when(userInfo.getString("preferred_username")).thenReturn("blocked-user");
        doReturn(userInfo).when(identity).getAttribute("userinfo");

        UserEntity blocked = new UserEntity();
        blocked.setId(UUID.randomUUID());
        blocked.setState(UserStateEnum.BLOCKED);
        when(userService.upsertFromOidc(any(), any(), any(), any())).thenReturn(blocked);

        assertThrows(AuthenticationFailedException.class, () -> supplier.augment(identity));
    }

    @Test
    void get_returnsIdentityWithCorrectRoleAndAttributes() {
        UserInfo userInfo = mock(UserInfo.class);
        when(userInfo.getString("sub")).thenReturn("sub-active");
        when(userInfo.getString("email")).thenReturn("active@test.com");
        when(userInfo.getString("preferred_username")).thenReturn("active-user");
        doReturn(userInfo).when(identity).getAttribute("userinfo");

        UUID userId = UUID.randomUUID();
        UserEntity user = buildActiveUser("editor");
        user.setId(userId);
        when(userService.upsertFromOidc(any(), any(), any(), any())).thenReturn(user);
        stubIdentityForBuilder();

        SecurityIdentity result = supplier.augment(identity);

        assertTrue(result.getRoles().contains("editor"));
        assertEquals(userId, result.getAttribute("user_id"));
        assertEquals("oidc", result.getAttribute("auth_source"));
        assertEquals(user, result.getAttribute("user"));
    }

    @Test
    void get_prefersPreferredUsernameOverNicknameAndName() {
        UserInfo userInfo = mock(UserInfo.class);
        when(userInfo.getString("sub")).thenReturn("sub-1");
        when(userInfo.getString("email")).thenReturn("user@test.com");
        when(userInfo.getString("preferred_username")).thenReturn("pref-name");
        doReturn(userInfo).when(identity).getAttribute("userinfo");

        UserEntity user = buildActiveUser("user");
        when(userService.upsertFromOidc("sub-1", "user@test.com", "pref-name", null)).thenReturn(user);
        stubIdentityForBuilder();

        supplier.augment(identity);

        verify(userService).upsertFromOidc("sub-1", "user@test.com", "pref-name", null);
    }

    @Test
    void get_fallsBackToNicknameWhenPreferredUsernameAbsent() {
        UserInfo userInfo = mock(UserInfo.class);
        when(userInfo.getString("sub")).thenReturn("sub-2");
        when(userInfo.getString("email")).thenReturn("user@test.com");
        when(userInfo.getString("preferred_username")).thenReturn(null);
        when(userInfo.getString("nickname")).thenReturn("nick-name");
        doReturn(userInfo).when(identity).getAttribute("userinfo");

        UserEntity user = buildActiveUser("user");
        when(userService.upsertFromOidc("sub-2", "user@test.com", "nick-name", null)).thenReturn(user);
        stubIdentityForBuilder();

        supplier.augment(identity);

        verify(userService).upsertFromOidc("sub-2", "user@test.com", "nick-name", null);
    }

    @Test
    void get_passesPictureClaimAsAvatar() {
        UserInfo userInfo = mock(UserInfo.class);
        when(userInfo.getString("sub")).thenReturn("sub-3");
        when(userInfo.getString("email")).thenReturn("user@test.com");
        when(userInfo.getString("preferred_username")).thenReturn("pic-user");
        lenient().when(userInfo.getString("picture")).thenReturn("https://idp/avatar.png");
        doReturn(userInfo).when(identity).getAttribute("userinfo");

        UserEntity user = buildActiveUser("user");
        when(userService.upsertFromOidc("sub-3", "user@test.com", "pic-user",
                "https://idp/avatar.png")).thenReturn(user);
        stubIdentityForBuilder();

        supplier.augment(identity);

        verify(userService).upsertFromOidc("sub-3", "user@test.com", "pic-user",
                "https://idp/avatar.png");
    }

    @Test
    void get_fallsBackToAvatarUrlClaimWhenPictureAbsent() {
        UserInfo userInfo = mock(UserInfo.class);
        when(userInfo.getString("sub")).thenReturn("sub-4");
        when(userInfo.getString("email")).thenReturn("user@test.com");
        when(userInfo.getString("preferred_username")).thenReturn("gitlab-user");
        lenient().when(userInfo.getString("picture")).thenReturn("  ");
        lenient().when(userInfo.getString("avatar_url")).thenReturn("https://gitlab/avatar.png");
        doReturn(userInfo).when(identity).getAttribute("userinfo");

        UserEntity user = buildActiveUser("user");
        when(userService.upsertFromOidc("sub-4", "user@test.com", "gitlab-user",
                "https://gitlab/avatar.png")).thenReturn(user);
        stubIdentityForBuilder();

        supplier.augment(identity);

        verify(userService).upsertFromOidc("sub-4", "user@test.com", "gitlab-user",
                "https://gitlab/avatar.png");
    }

    @Test
    void get_passesNullAvatarWhenProviderSendsNoPictureClaim() {
        UserInfo userInfo = mock(UserInfo.class);
        when(userInfo.getString("sub")).thenReturn("sub-5");
        when(userInfo.getString("email")).thenReturn("user@test.com");
        when(userInfo.getString("preferred_username")).thenReturn("no-pic-user");
        doReturn(userInfo).when(identity).getAttribute("userinfo");

        UserEntity user = buildActiveUser("user");
        when(userService.upsertFromOidc("sub-5", "user@test.com", "no-pic-user", null))
                .thenReturn(user);
        stubIdentityForBuilder();

        supplier.augment(identity);

        verify(userService).upsertFromOidc("sub-5", "user@test.com", "no-pic-user", null);
    }

    @Test
    void get_survivesAnAvatarClaimThatIsNotAString() {
        UserInfo userInfo = mock(UserInfo.class);
        when(userInfo.getString("sub")).thenReturn("sub-6");
        when(userInfo.getString("email")).thenReturn("user@test.com");
        when(userInfo.getString("preferred_username")).thenReturn("odd-pic-user");
        lenient().when(userInfo.getString("picture")).thenThrow(new ClassCastException("not a string"));
        lenient().when(userInfo.getString("avatar_url")).thenReturn("https://idp/fallback.png");
        doReturn(userInfo).when(identity).getAttribute("userinfo");

        UserEntity user = buildActiveUser("user");
        when(userService.upsertFromOidc("sub-6", "user@test.com", "odd-pic-user",
                "https://idp/fallback.png")).thenReturn(user);
        stubIdentityForBuilder();

        supplier.augment(identity);

        verify(userService).upsertFromOidc("sub-6", "user@test.com", "odd-pic-user",
                "https://idp/fallback.png");
    }

    // --- helpers ---

    private UserEntity buildActiveUser(String role) {
        UserEntity u = new UserEntity();
        u.setId(UUID.randomUUID());
        u.setRole(role);
        u.setState(UserStateEnum.ACTIVE);
        return u;
    }

    private void stubIdentityForBuilder() {
        lenient().when(identity.isAnonymous()).thenReturn(false);
        lenient().when(identity.getRoles()).thenReturn(Set.of());
        lenient().when(identity.getCredentials()).thenReturn(Set.of());
        lenient().when(identity.getAttributes()).thenReturn(Map.of());
        lenient().when(identity.getPrincipal()).thenReturn(() -> "test-principal");
    }
}
