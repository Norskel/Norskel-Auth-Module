package net.norskel.auth.module.runtime;

import io.quarkus.oidc.UserInfo;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import net.norskel.auth.module.runtime.config.AuthRuntimeConfig;
import net.norskel.auth.module.runtime.entities.UserEntity;
import net.norskel.auth.module.runtime.enums.UserStateEnum;
import net.norskel.auth.module.runtime.spi.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;
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

    @InjectMocks
    OIDCSecurityIdentitySupplier supplier;

    @BeforeEach
    void setUp() {
        supplier.setIdentity(identity);
    }

    @Test
    void get_throwsWhenUserInfoMissing() {
        doReturn(null).when(identity).getAttribute("userinfo");

        assertThrows(AuthenticationFailedException.class, () -> supplier.get());
        verify(userService, never()).upsertFromOidc(any(), any(), any());
    }

    @Test
    void get_throwsWhenSubjectIsNull() {
        UserInfo userInfo = mock(UserInfo.class);
        when(userInfo.getString("sub")).thenReturn(null);
        doReturn(userInfo).when(identity).getAttribute("userinfo");

        assertThrows(AuthenticationFailedException.class, () -> supplier.get());
        verify(userService, never()).upsertFromOidc(any(), any(), any());
    }

    @Test
    void get_throwsWhenSubjectIsBlank() {
        UserInfo userInfo = mock(UserInfo.class);
        when(userInfo.getString("sub")).thenReturn("   ");
        doReturn(userInfo).when(identity).getAttribute("userinfo");

        assertThrows(AuthenticationFailedException.class, () -> supplier.get());
        verify(userService, never()).upsertFromOidc(any(), any(), any());
    }

    @Test
    void get_throwsWhenUserSyncFails() {
        UserInfo userInfo = mock(UserInfo.class);
        when(userInfo.getString("sub")).thenReturn("sub-x");
        when(userInfo.getString("email")).thenReturn("user@test.com");
        when(userInfo.getString("preferred_username")).thenReturn("testuser");
        doReturn(userInfo).when(identity).getAttribute("userinfo");
        when(userService.upsertFromOidc(any(), any(), any()))
                .thenThrow(new RuntimeException("DB error"));

        assertThrows(AuthenticationFailedException.class, () -> supplier.get());
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
        when(userService.upsertFromOidc(any(), any(), any())).thenReturn(blocked);

        assertThrows(AuthenticationFailedException.class, () -> supplier.get());
        verify(userService, never()).updateLastLogin(any());
    }

    @Test
    void get_updatesLastLoginForActiveUser() {
        UserInfo userInfo = mock(UserInfo.class);
        when(userInfo.getString("sub")).thenReturn("sub-active");
        when(userInfo.getString("email")).thenReturn("active@test.com");
        when(userInfo.getString("preferred_username")).thenReturn("active-user");
        doReturn(userInfo).when(identity).getAttribute("userinfo");

        UserEntity user = buildActiveUser("user");
        when(userService.upsertFromOidc(any(), any(), any())).thenReturn(user);
        stubIdentityForBuilder();

        supplier.get();

        verify(userService).updateLastLogin(user);
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
        when(userService.upsertFromOidc(any(), any(), any())).thenReturn(user);
        stubIdentityForBuilder();

        SecurityIdentity result = supplier.get();

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
        when(userService.upsertFromOidc("sub-1", "user@test.com", "pref-name")).thenReturn(user);
        stubIdentityForBuilder();

        supplier.get();

        verify(userService).upsertFromOidc("sub-1", "user@test.com", "pref-name");
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
        when(userService.upsertFromOidc("sub-2", "user@test.com", "nick-name")).thenReturn(user);
        stubIdentityForBuilder();

        supplier.get();

        verify(userService).upsertFromOidc("sub-2", "user@test.com", "nick-name");
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
