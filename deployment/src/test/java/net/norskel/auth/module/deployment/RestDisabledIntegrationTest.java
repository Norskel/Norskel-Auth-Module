package net.norskel.auth.module.deployment;

import io.quarkus.security.Authenticated;
import io.quarkus.test.QuarkusUnitTest;
import io.quarkus.test.common.http.TestHTTPResource;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import net.norskel.auth.module.runtime.AuthAttributes;
import net.norskel.auth.module.runtime.CurrentUser;
import net.norskel.auth.module.runtime.entities.UserEntity;
import net.norskel.auth.module.runtime.spi.ApiKeyService;
import net.norskel.auth.module.runtime.spi.UserService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The host application turns off the extension's REST endpoints and serves its own,
 * built on the services and on {@link CurrentUser}. Authentication must keep working:
 * only the {@code /auth/*} routes disappear.
 */
class RestDisabledIntegrationTest {

    @RegisterExtension
    static final QuarkusUnitTest APP = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar
                    .addClass(WhoAmIResource.class)
                    .addAsResource("application.properties")
                    .addAsResource("publicKey.pem")
                    .addAsResource("privateKey.pem"))
            .overrideConfigKey("norskel-auth-build.rest-enabled", "false");

    @Inject
    UserService userService;

    @Inject
    ApiKeyService apiKeyService;

    @TestHTTPResource("/")
    URL root;

    private final HttpClient http = HttpClient.newHttpClient();

    @Test
    void extensionEndpointsAreGone_butAuthenticationStillWorks() throws Exception {
        UserEntity user = userService.create(UserEntity.builder()
                .username("host-user")
                .email("host@test.com")
                .role("user")
                .oidcId("oidc-host")
                .build());
        String key = apiKeyService.create(user.getId(), "host-key", Duration.ofDays(1)).token();

        assertEquals(404, get("/auth/users/me", key).statusCode(),
                "/auth/users must not be served when rest-enabled=false");
        assertEquals(404, get("/auth/api-keys/me", key).statusCode(),
                "/auth/api-keys must not be served when rest-enabled=false");

        HttpResponse<String> whoami = get("/host/whoami", key);
        assertEquals(200, whoami.statusCode(), whoami.body());
        assertEquals("host-user|" + AuthAttributes.SOURCE_API_KEY + "|false", whoami.body());

        assertEquals(401, get("/host/whoami", null).statusCode(),
                "the host endpoint must still be secured");
    }

    @Test
    void currentUser_flagsServiceKeys() throws Exception {
        String key = apiKeyService
                .createServiceKey("host-worker", "worker-key", "user", Duration.ofDays(1))
                .token();

        HttpResponse<String> whoami = get("/host/whoami", key);
        assertEquals(200, whoami.statusCode(), whoami.body());
        assertEquals("host-worker|" + AuthAttributes.SOURCE_SERVICE_API_KEY + "|true", whoami.body());
    }

    private HttpResponse<String> get(String path, String apiKey) throws Exception {
        HttpRequest.Builder req = HttpRequest.newBuilder(URI.create(root.toString()).resolve(path)).GET();
        if (apiKey != null) {
            req.header("X-Api-Key", apiKey);
        }
        return http.send(req.build(), HttpResponse.BodyHandlers.ofString());
    }

    /** A host-application endpoint relying only on {@link CurrentUser}. */
    @Path("/host/whoami")
    @Authenticated
    public static class WhoAmIResource {

        @Inject
        CurrentUser currentUser;

        @GET
        @Produces(MediaType.TEXT_PLAIN)
        public String whoami() {
            return currentUser.require().getUsername()
                    + "|" + currentUser.authSource().orElse("none")
                    + "|" + currentUser.isService();
        }
    }
}
