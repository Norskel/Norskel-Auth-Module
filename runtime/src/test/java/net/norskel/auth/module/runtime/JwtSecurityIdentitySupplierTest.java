package net.norskel.auth.module.runtime;

import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.SecurityIdentity;
import net.norskel.auth.module.runtime.entities.UserEntity;
import net.norskel.auth.module.runtime.enums.UserStateEnum;
import net.norskel.auth.module.runtime.spi.ApiKeyService;
import net.norskel.auth.module.runtime.spi.UserService;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Tests for JwtSecurityIdentitySupplier.
 */
@ExtendWith(MockitoExtension.class)
class JwtSecurityIdentitySupplierTest {

    @Mock
    SecurityIdentity identity;

    @Mock
    ApiKeyService apiKeyService;

    @Mock
    UserService userService;

    @InjectMocks
    JwtSecurityIdentitySupplier supplier;

    @Mock
    JsonWebToken jwt;

    @BeforeEach
    void setUp() {
        supplier.setIdentity(identity);
        lenient().when(identity.getPrincipal()).thenReturn(jwt);
    }

    @Test
    void get_throwsForNonUuidJti() {
        when(jwt.getTokenID()).thenReturn("not-a-uuid");

        assertThrows(AuthenticationFailedException.class, supplier::get);
        verify(apiKeyService, never()).check(any());
    }

    @Test
    void get_throwsForNullJti() {
        when(jwt.getTokenID()).thenReturn(null);

        assertThrows(AuthenticationFailedException.class, supplier::get);
    }

    @Test
    void get_throwsForRevokedOrInvalidToken() {
        UUID tokenId = UUID.randomUUID();
        when(jwt.getTokenID()).thenReturn(tokenId.toString());
        when(apiKeyService.check(tokenId)).thenReturn(false);

        assertThrows(AuthenticationFailedException.class, supplier::get);
        verify(userService, never()).findById(any());
    }

    @Test
    void get_throwsWhenSubjectIsNotAUuid() {
        UUID tokenId = UUID.randomUUID();
        when(jwt.getTokenID()).thenReturn(tokenId.toString());
        when(apiKeyService.check(tokenId)).thenReturn(true);
        when(jwt.getSubject()).thenReturn("not-a-uuid");

        assertThrows(AuthenticationFailedException.class, supplier::get);
        verify(userService, never()).findById(any());
    }

    @Test
    void get_throwsForUnknownUser() {
        UUID tokenId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();
        when(jwt.getTokenID()).thenReturn(tokenId.toString());
        when(apiKeyService.check(tokenId)).thenReturn(true);
        when(jwt.getSubject()).thenReturn(userId.toString());
        when(userService.findById(userId)).thenThrow(new NoSuchElementException("no user"));

        assertThrows(AuthenticationFailedException.class, supplier::get);
    }

    @Test
    void get_throwsForBannedUser() {
        UUID tokenId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();
        when(jwt.getTokenID()).thenReturn(tokenId.toString());
        when(apiKeyService.check(tokenId)).thenReturn(true);
        when(jwt.getSubject()).thenReturn(userId.toString());

        UserEntity banned = new UserEntity();
        banned.setId(userId);
        banned.setState(UserStateEnum.BLOCKED);
        when(userService.findById(userId)).thenReturn(banned);

        assertThrows(AuthenticationFailedException.class, supplier::get);
    }

    @Test
    void get_returnsEnrichedIdentity_forValidToken() {
        UUID tokenId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();
        when(jwt.getTokenID()).thenReturn(tokenId.toString());
        when(apiKeyService.check(tokenId)).thenReturn(true);
        when(jwt.getSubject()).thenReturn(userId.toString());

        UserEntity user = new UserEntity();
        user.setId(userId);
        user.setRole("editor");
        user.setState(UserStateEnum.ACTIVE);
        when(userService.findById(userId)).thenReturn(user);

        stubIdentityForBuilder();

        SecurityIdentity result = supplier.get();

        assertNotNull(result);
        assertTrue(result.getRoles().contains("editor"));
        assertEquals(userId, result.getAttribute("user_id"));
        assertEquals("api-key", result.getAttribute("auth_source"));
        assertEquals(user, result.getAttribute("user"));
    }

    // --- helpers ---

    private void stubIdentityForBuilder() {
        lenient().when(identity.isAnonymous()).thenReturn(false);
        lenient().when(identity.getRoles()).thenReturn(Set.of());
        lenient().when(identity.getCredentials()).thenReturn(Set.of());
        lenient().when(identity.getAttributes()).thenReturn(Map.of());
    }
}
