package net.norskel.auth.module.runtime;

import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.smallrye.jwt.runtime.auth.JsonWebTokenCredential;
import net.norskel.auth.module.runtime.spi.ApiKeyService;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
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

    @InjectMocks
    JwtSecurityIdentitySupplier supplier;

    @Mock
    JsonWebToken jwt;

    @Mock
    JsonWebTokenCredential jwtCredential;

    @BeforeEach
    void setUp() {
        supplier.setIdentity(identity);
        when(identity.getPrincipal()).thenReturn(jwt);
        when(identity.getCredential(JsonWebTokenCredential.class)).thenReturn(jwtCredential);
        when(jwtCredential.getToken()).thenReturn("raw.jwt.token");
        when(jwt.getSubject()).thenReturn("user-sub-123");
    }

    @Test
    void get_throwsForNonUuidJti() {
        when(jwt.getTokenID()).thenReturn("not-a-uuid");

        assertThrows(AuthenticationFailedException.class, () -> supplier.get());
        verify(apiKeyService, never()).check(any());
    }

    @Test
    void get_throwsForNullJti() {
        when(jwt.getTokenID()).thenReturn(null);

        assertThrows(AuthenticationFailedException.class, () -> supplier.get());
    }

    @Test
    void get_throwsForRevokedOrInvalidToken() {
        UUID tokenId = UUID.randomUUID();
        when(jwt.getTokenID()).thenReturn(tokenId.toString());
        when(apiKeyService.check(tokenId)).thenReturn(false);

        assertThrows(AuthenticationFailedException.class, () -> supplier.get());
    }

    @Test
    void get_returnsEnrichedIdentity_forValidToken() {
        UUID tokenId = UUID.randomUUID();
        when(jwt.getTokenID()).thenReturn(tokenId.toString());
        when(apiKeyService.check(tokenId)).thenReturn(true);

        stubIdentityForBuilder();

        SecurityIdentity result = supplier.get();

        assertNotNull(result);
        assertTrue(result.getRoles().contains("User"));
    }

    // --- helpers ---

    private void stubIdentityForBuilder() {
        lenient().when(identity.isAnonymous()).thenReturn(false);
        lenient().when(identity.getRoles()).thenReturn(Set.of());
        lenient().when(identity.getCredentials()).thenReturn(Set.of());
        lenient().when(identity.getAttributes()).thenReturn(Map.of());
    }
}
