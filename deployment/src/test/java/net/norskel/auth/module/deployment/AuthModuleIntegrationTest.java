package net.norskel.auth.module.deployment;

import io.quarkus.test.QuarkusUnitTest;
import io.quarkus.test.common.http.TestHTTPResource;
import jakarta.inject.Inject;
import net.norskel.auth.module.runtime.entities.UserEntity;
import net.norskel.auth.module.runtime.enums.UserTypeEnum;
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
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end test of the HTTP layer and the API-key authentication flow.
 *
 * <p>Boots the extension inside a real Quarkus application (REST layer active,
 * OIDC on the classpath) and exercises {@code /auth/users/me} with an API key.
 * This verifies that the resources are actually served (a REST implementation is
 * present), that API-key requests are dispatched to smallrye-jwt via the
 * {@code X-Api-Key} header without a custom mechanism, and that the augmentor
 * propagates the identity end-to-end.
 */
class AuthModuleIntegrationTest {

    @RegisterExtension
    static final QuarkusUnitTest APP = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar
                    .addAsResource("application.properties")
                    .addAsResource("publicKey.pem")
                    .addAsResource("privateKey.pem"));

    @Inject
    UserService userService;

    @Inject
    ApiKeyService apiKeyService;

    @TestHTTPResource("/auth/users/me")
    URL meUrl;

    private final HttpClient http = HttpClient.newHttpClient();

    @Test
    void apiKeyAuthentication_endToEnd() throws Exception {
        // Seed a user and mint a real signed API key for it.
        UserEntity user = userService.create(UserEntity.builder()
                .username("ci-bot")
                .email("ci@test.com")
                .role("admin")
                .oidcId("oidc-ci")
                .build());
        ApiKeyService.IssuedApiKey issued =
                apiKeyService.create(user.getId(), "ci-key", Duration.ofDays(30));
        String token = issued.token();

        // 1. No credential -> 401 (proves the endpoint is served AND secured).
        assertEquals(401, get(null).statusCode(),
                "unauthenticated request must be rejected");

        // 2. Valid API key -> 200, returns the current user.
        HttpResponse<String> ok = get(token);
        assertEquals(200, ok.statusCode(), "valid API key must authenticate");
        assertTrue(ok.body().contains("ci-bot"),
                "response should carry the resolved user, was: " + ok.body());

        // 3. Revoked key -> 401 (revocation is enforced per request).
        apiKeyService.revoke(issued.apiKey().getId(), user.getId());
        assertEquals(401, get(token).statusCode(),
                "revoked API key must be rejected");
    }

    /**
     * Domain failures must surface as their proper HTTP status, not as 500.
     * Exercised over HTTP because the mapping only exists once the extension's
     * {@code AuthExceptionMappers} is discovered by the REST layer — a unit test
     * on the services would pass even with no mapper registered at all.
     */
    @Test
    void domainErrors_mapToProperStatusCodes() throws Exception {
        UserEntity admin = userService.create(UserEntity.builder()
                .username("mapper-admin")
                .email("admin@test.com")
                .role("admin")
                .oidcId("oidc-mapper-admin")
                .build());
        String adminKey = apiKeyService
                .create(admin.getId(), "admin-key", Duration.ofDays(1)).token();

        // Unknown user -> 404 (AuthNotFoundException), previously a 500.
        HttpResponse<String> notFound =
                send("GET", "/auth/users/" + UUID.randomUUID(), adminKey, null);
        assertEquals(404, notFound.statusCode(), "unknown user must be 404");
        // Pins the response to AuthExceptionMappers rather than to any default
        // handler that might also produce a 404.
        assertTrue(notFound.body().contains("\"error\":\"not_found\""),
                "404 body must come from AuthExceptionMappers, was: " + notFound.body());

        // Non-positive lifetime -> 400, rejected by the resource before the service.
        assertEquals(400,
                send("POST", "/auth/api-keys/me", adminKey,
                        "{\"name\":\"bad\",\"lifetimeDays\":0}").statusCode(),
                "non-positive lifetime must be 400");

        // Omitted lifetime with no default-ttl configured -> 400 from
        // AuthValidationException. Unlike the case above this one travels
        // through the service, so it is what actually covers the mapper.
        assertEquals(400,
                send("POST", "/auth/api-keys/me", adminKey,
                        "{\"name\":\"no-ttl\"}").statusCode(),
                "missing lifetime with no configured default must be 400");

        // Duplicate username -> 409 (AuthConflictException), previously a 500.
        assertEquals(409,
                send("POST", "/auth/users", adminKey,
                        "{\"username\":\"mapper-admin\",\"email\":\"dup@test.com\","
                                + "\"role\":\"user\",\"oidc_id\":\"oidc-dup\"}").statusCode(),
                "duplicate username must be 409");

        // Revoking a key you do not own -> 403 (AuthForbiddenException).
        UserEntity other = userService.create(UserEntity.builder()
                .username("mapper-other")
                .email("other@test.com")
                .role("user")
                .oidcId("oidc-other")
                .build());
        UUID otherKeyId = apiKeyService
                .create(other.getId(), "other-key", Duration.ofDays(1)).apiKey().getId();
        assertEquals(403,
                send("DELETE", "/auth/api-keys/me/" + otherKeyId, adminKey, null).statusCode(),
                "revoking someone else's key must be 403");

        // Deleting a user now works instead of throwing UnsupportedOperationException.
        UserEntity victim = userService.create(UserEntity.builder()
                .username("mapper-victim")
                .email("victim@test.com")
                .role("user")
                .oidcId("oidc-victim")
                .build());
        assertEquals(204,
                send("DELETE", "/auth/users/" + victim.getId(), adminKey, null).statusCode(),
                "deleting an existing user must be 204");
        assertEquals(404,
                send("DELETE", "/auth/users/" + victim.getId(), adminKey, null).statusCode(),
                "deleting an already-deleted user must be 404");
    }

    /**
     * {@code GET /auth/api-keys/service} must not be swallowed by the
     * {@code /auth/api-keys/{id}} template that shares its prefix.
     */
    @Test
    void servicePath_takesPrecedenceOverTheIdTemplate() throws Exception {
        HttpResponse<String> r =
                send("GET", "/auth/api-keys/service", adminKeyFor("path-admin"), null);
        assertEquals(200, r.statusCode(),
                "literal /service must win over /{id}, was: " + r.statusCode() + " " + r.body());
    }

    /**
     * A service key is an ordinary key owned by a {@code SERVICE} user. It takes
     * its role from that user, may read but not mutate its own record, and dies
     * with it — the whole point of modelling a service as a user row rather than
     * as a second kind of key.
     */
    @Test
    void serviceApiKey_isOwnedByAServiceUser() throws Exception {
        ApiKeyService.IssuedApiKey issued = apiKeyService.createServiceKey(
                "billing-worker", "nightly-batch", "admin", Duration.ofDays(30));
        String serviceKey = issued.token();

        // The key is owned like any other; there is no separate key shape.
        UUID ownerId = issued.apiKey().getUserId();
        assertNotNull(ownerId, "a service key must be owned by its service user");
        UserEntity owner = userService.findById(ownerId);
        assertEquals(UserTypeEnum.SERVICE, owner.getType());
        assertEquals("billing-worker", owner.getUsername());
        assertNull(owner.getOidcId(), "a service never logs in through OIDC");

        // 1. Role comes from the owning service user.
        assertEquals(200, send("GET", "/auth/users", serviceKey, null).statusCode(),
                "service key must satisfy @RolesAllowed(\"admin\")");

        // 2. It may read its own record...
        HttpResponse<String> me = send("GET", "/auth/users/me", serviceKey, null);
        assertEquals(200, me.statusCode(), "a service may read its own row, was: " + me.body());
        assertTrue(me.body().contains("billing-worker"), me.body());

        // 3. ...but not mutate it, so a leaked key cannot mint itself a successor.
        HttpResponse<String> mint = send("POST", "/auth/api-keys/me", serviceKey,
                "{\"name\":\"self-issued\",\"lifetimeDays\":30}");
        assertEquals(403, mint.statusCode(),
                "a service must not issue keys for itself, was: " + mint.body());
        assertTrue(mint.body().contains("\"error\":\"forbidden\""), mint.body());

        // 4. A second key for the same service is allowed: that is key rotation.
        assertEquals(200,
                send("POST", "/auth/api-keys/service", serviceKey,
                        "{\"serviceName\":\"billing-worker\",\"name\":\"rotated\","
                                + "\"role\":\"admin\",\"lifetimeDays\":30}").statusCode(),
                "rotating a service key must be allowed");

        // 5. But not with a different role — that would escalate silently.
        assertEquals(409,
                send("POST", "/auth/api-keys/service", serviceKey,
                        "{\"serviceName\":\"billing-worker\",\"name\":\"escalate\","
                                + "\"role\":\"superuser\",\"lifetimeDays\":30}").statusCode(),
                "changing a service's role while minting a key must be refused");

        // 6. Listed among service keys.
        HttpResponse<String> serviceList = send("GET", "/auth/api-keys/service", serviceKey, null);
        assertEquals(200, serviceList.statusCode());

        // 7. Blocking the service user is the kill switch: every key it owns
        //    stops working at once, without revoking them individually.
        assertEquals(204,
                send("POST", "/auth/users/" + ownerId + "/ban",
                        adminKeyFor("banner-admin"), null).statusCode());
        assertEquals(401, send("GET", "/auth/users", serviceKey, null).statusCode(),
                "blocking the service must disable its keys");
    }

    /**
     * Provenance: who created a key or a service must be recorded, and must not
     * be settable by the client. Without this, an admin can stand up a
     * long-lived service and leave no trace once their own account is gone.
     */
    @Test
    void createdBy_isRecordedAndCannotBeForged() throws Exception {
        UserEntity admin = userService.create(UserEntity.builder()
                .username("prov-admin").email("prov@test.com")
                .role("admin").oidcId("oidc-prov").build());
        String adminKey = apiKeyService
                .create(admin.getId(), "prov-key", Duration.ofDays(1)).token();

        // 1. A service and its key both record the admin who created them.
        HttpResponse<String> created = send("POST", "/auth/api-keys/service", adminKey,
                "{\"serviceName\":\"prov-service\",\"name\":\"k\","
                        + "\"role\":\"billing\",\"lifetimeDays\":30}");
        assertEquals(200, created.statusCode(), created.body());

        HttpResponse<String> keys = send("GET", "/auth/api-keys/service", adminKey, null);
        assertTrue(keys.body().contains("\"created_by\":\"" + admin.getId() + "\""),
                "the service key must record its creator, was: " + keys.body());

        HttpResponse<String> users = send("GET", "/auth/users", adminKey, null);
        assertTrue(users.body().contains("\"created_by\":\"" + admin.getId() + "\""),
                "the SERVICE row must record its creator, was: " + users.body());

        // 2. A client cannot choose its own created_by: the field is READ_ONLY in
        //    JSON, so the forged value is ignored and the caller is recorded.
        UUID forged = UUID.randomUUID();
        HttpResponse<String> forgedUser = send("POST", "/auth/users", adminKey,
                "{\"username\":\"forger\",\"email\":\"f@test.com\",\"role\":\"user\","
                        + "\"oidc_id\":\"oidc-forger\",\"created_by\":\"" + forged + "\"}");
        assertEquals(201, forgedUser.statusCode(), forgedUser.body());
        assertFalse(forgedUser.body().contains(forged.toString()),
                "a client must not be able to set created_by, was: " + forgedUser.body());
        assertTrue(forgedUser.body().contains("\"created_by\":\"" + admin.getId() + "\""),
                "created_by must be the acting admin, was: " + forgedUser.body());
    }

    private String adminKeyFor(String username) {
        UserEntity u = userService.create(UserEntity.builder()
                .username(username)
                .email(username + "@test.com")
                .role("admin")
                .oidcId("oidc-" + username)
                .build());
        return apiKeyService.create(u.getId(), username + "-key", Duration.ofDays(1)).token();
    }

    private HttpResponse<String> get(String apiKey) throws Exception {
        return send("GET", "/auth/users/me", apiKey, null);
    }

    private HttpResponse<String> send(String method, String path, String apiKey, String body)
            throws Exception {
        URI uri = URI.create(meUrl.toString()).resolve(path);
        HttpRequest.Builder req = HttpRequest.newBuilder(uri);
        if (apiKey != null) {
            req.header("X-Api-Key", apiKey);
        }
        if (body != null) {
            req.header("Content-Type", "application/json");
            req.method(method, HttpRequest.BodyPublishers.ofString(body));
        } else {
            req.method(method, HttpRequest.BodyPublishers.noBody());
        }
        return http.send(req.build(), HttpResponse.BodyHandlers.ofString());
    }
}
