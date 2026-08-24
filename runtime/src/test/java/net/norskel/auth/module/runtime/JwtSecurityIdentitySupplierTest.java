package net.norskel.auth.module.runtime;

import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.SecurityIdentity;
import net.norskel.auth.module.runtime.entities.UserEntity;
import net.norskel.auth.module.runtime.enums.UserStateEnum;
import net.norskel.auth.module.runtime.enums.UserTypeEnum;
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
        lenient().when(identity.getPrincipal()).thenReturn(jwt);
    }

    @Test
    void get_throwsForNonUuidJti() {
        when(jwt.getTokenID()).thenReturn("not-a-uuid");

        assertThrows(AuthenticationFailedException.class, () -> supplier.augment(identity));
        verify(apiKeyService, never()).check(any());
    }

    @Test
    void get_throwsForNullJti() {
        when(jwt.getTokenID()).thenReturn(null);

        assertThrows(AuthenticationFailedException.class, () -> supplier.augment(identity));
    }

    @Test
    void get_throwsForRevokedOrInvalidToken() {
        UUID tokenId = UUID.randomUUID();
        when(jwt.getTokenID()).thenReturn(tokenId.toString());
        when(apiKeyService.check(tokenId)).thenReturn(false);

        assertThrows(AuthenticationFailedException.class, () -> supplier.augment(identity));
        verify(userService, never()).findById(any());
    }

    @Test
    void get_throwsWhenSubjectIsNotAUuid() {
        UUID tokenId = UUID.randomUUID();
        when(jwt.getTokenID()).thenReturn(tokenId.toString());
        when(apiKeyService.check(tokenId)).thenReturn(true);
        when(jwt.getSubject()).thenReturn("not-a-uuid");

        assertThrows(AuthenticationFailedException.class, () -> supplier.augment(identity));
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

        assertThrows(AuthenticationFailedException.class, () -> supplier.augment(identity));
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

        assertThrows(AuthenticationFailedException.class, () -> supplier.augment(identity));
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

        SecurityIdentity result = supplier.augment(identity);

        assertNotNull(result);
        assertTrue(result.getRoles().contains("editor"));
        assertEquals(userId, result.getAttribute("user_id"));
        assertEquals("api-key", result.getAttribute("auth_source"));
        assertEquals(user, result.getAttribute("user"));
    }

    // --- service identities ---

    @Test
    void augment_returnsServiceIdentity_whenTheOwningUserIsAService() {
        UUID tokenId = UUID.randomUUID();
        UUID svcId = UUID.randomUUID();
        when(jwt.getTokenID()).thenReturn(tokenId.toString());
        when(apiKeyService.check(tokenId)).thenReturn(true);
        when(jwt.getSubject()).thenReturn(svcId.toString());

        UserEntity svc = new UserEntity();
        svc.setId(svcId);
        svc.setUsername("billing-worker");
        svc.setRole("billing");
        svc.setType(UserTypeEnum.SERVICE);
        svc.setState(UserStateEnum.ACTIVE);
        when(userService.findById(svcId)).thenReturn(svc);
        stubIdentityForBuilder();

        SecurityIdentity result = supplier.augment(identity);

        assertTrue(result.getRoles().contains("billing"));
        assertEquals("billing-worker", result.getAttribute(AuthAttributes.SERVICE_NAME));
        assertEquals(AuthAttributes.SOURCE_SERVICE_API_KEY,
                result.getAttribute(AuthAttributes.AUTH_SOURCE));
        // A service is a user row, so unlike the previous design it does carry
        // user attributes. Callers distinguish on auth_source, not on absence.
        assertEquals(svcId, result.getAttribute(AuthAttributes.USER_ID));
        assertEquals(svc, result.getAttribute(AuthAttributes.USER));
    }

    @Test
    void augment_marksHumanOwnersWithThePlainApiKeySource() {
        UUID tokenId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();
        when(jwt.getTokenID()).thenReturn(tokenId.toString());
        when(apiKeyService.check(tokenId)).thenReturn(true);
        when(jwt.getSubject()).thenReturn(userId.toString());

        UserEntity human = new UserEntity();
        human.setId(userId);
        human.setUsername("alice");
        human.setRole("editor");
        human.setType(UserTypeEnum.HUMAN);
        human.setState(UserStateEnum.ACTIVE);
        when(userService.findById(userId)).thenReturn(human);
        stubIdentityForBuilder();

        SecurityIdentity result = supplier.augment(identity);

        assertEquals(AuthAttributes.SOURCE_API_KEY,
                result.getAttribute(AuthAttributes.AUTH_SOURCE));
        assertNull(result.getAttribute(AuthAttributes.SERVICE_NAME));
    }

    @Test
    void augment_throwsForServiceWithoutRole() {
        UUID tokenId = UUID.randomUUID();
        UUID svcId = UUID.randomUUID();
        when(jwt.getTokenID()).thenReturn(tokenId.toString());
        when(apiKeyService.check(tokenId)).thenReturn(true);
        when(jwt.getSubject()).thenReturn(svcId.toString());

        UserEntity svc = new UserEntity();
        svc.setId(svcId);
        svc.setUsername("svc");
        svc.setRole("  ");
        svc.setType(UserTypeEnum.SERVICE);
        svc.setState(UserStateEnum.ACTIVE);
        when(userService.findById(svcId)).thenReturn(svc);

        assertThrows(AuthenticationFailedException.class, () -> supplier.augment(identity));
    }

    @Test
    void augment_throwsWhenTheServiceUserIsBlocked() {
        // The kill switch the previous design lacked: blocking the service row
        // disables every key it owns, with no per-key revocation needed.
        UUID tokenId = UUID.randomUUID();
        UUID svcId = UUID.randomUUID();
        when(jwt.getTokenID()).thenReturn(tokenId.toString());
        when(apiKeyService.check(tokenId)).thenReturn(true);
        when(jwt.getSubject()).thenReturn(svcId.toString());

        UserEntity svc = new UserEntity();
        svc.setId(svcId);
        svc.setUsername("svc");
        svc.setRole("billing");
        svc.setType(UserTypeEnum.SERVICE);
        svc.setState(UserStateEnum.BLOCKED);
        when(userService.findById(svcId)).thenReturn(svc);

        assertThrows(AuthenticationFailedException.class, () -> supplier.augment(identity));
    }

    // --- helpers ---

    private void stubIdentityForBuilder() {
        lenient().when(identity.isAnonymous()).thenReturn(false);
        lenient().when(identity.getRoles()).thenReturn(Set.of());
        lenient().when(identity.getCredentials()).thenReturn(Set.of());
        lenient().when(identity.getAttributes()).thenReturn(Map.of());
    }
}
