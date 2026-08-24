package net.norskel.auth.example;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.keycloak.client.KeycloakTestClient;
import io.restassured.http.ContentType;
import io.restassured.http.Header;
import jakarta.inject.Inject;
import net.norskel.auth.module.runtime.entities.UserEntity;
import net.norskel.auth.module.runtime.spi.ApiKeyService;
import net.norskel.auth.module.runtime.spi.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Exercises the OIDC half of the extension against a real Keycloak.
 *
 * <p>Dev Services for Keycloak provides that Keycloak automatically — which is
 * why {@code quarkus.oidc.auth-server-url} must stay unset for the dev and test
 * profiles. Setting it disables Dev Services, and every assertion here would be
 * unreachable.
 *
 * <p>Everything else in the suite authenticates with an API key, so this is the
 * only coverage of {@code OIDCSecurityIdentitySupplier} and of
 * {@code UserServiceImpl.upsertFromOidc}.
 */
@QuarkusTest
class OidcFlowTest {

    private final KeycloakTestClient keycloak = new KeycloakTestClient();

    @Inject
    UserService userService;

    @Inject
    ApiKeyService apiKeyService;

    private String adminKey;

    @BeforeEach
    void mintAdminKey() {
        UserEntity admin = userService.create(UserEntity.builder()
                .username("oidc-test-admin-" + System.nanoTime())
                .email("oidc-admin@example.test")
                .role("admin")
                .oidcId("oidc-admin-" + System.nanoTime())
                .build());
        adminKey = apiKeyService
                .create(admin.getId(), "oidc-test-key", Duration.ofDays(1)).token();
    }

    /**
     * A Keycloak access token for alice, explicitly requested with the
     * {@code openid} scope.
     *
     * <p>The scope is not optional here. This extension requires
     * {@code user-info-required=true}, and Keycloak's userinfo endpoint answers
     * 403 for a token that lacks {@code openid} — which surfaces as a bare 401
     * from the application. {@code getAccessToken("alice")} alone requests only
     * {@code microprofile-jwt} and therefore cannot work with this extension.
     */
    private Header bearer() {
        String token = keycloak.getAccessToken(
                "alice", "alice", "quarkus-app", "secret", List.of("openid"));
        return new Header("Authorization", "Bearer " + token);
    }

    private Header apiKey() {
        return new Header("X-Api-Key", adminKey);
    }

    /** Logs in over OIDC and returns the user id the extension resolved. */
    private UUID loginAndGetUserId() {
        String id = given().header(bearer())
                .when().get("/reports/whoami")
                .then().statusCode(200)
                .extract().path("userId");
        assertNotNull(id, "an OIDC identity must carry a user id");
        return UUID.fromString(id);
    }

    @Test
    void oidcTokenAuthenticatesAndReportsItsSource() {
        given().header(bearer())
                .when().get("/reports/whoami")
                .then().statusCode(200)
                .body("authSource", equalTo("oidc"))
                .body("userId", notNullValue())
                .body("serviceName", org.hamcrest.Matchers.nullValue());
    }

    @Test
    void firstOidcLoginAutoCreatesTheUser() {
        UserEntity alice = userService.findById(loginAndGetUserId());

        assertNotNull(alice.getOidcId(), "the user must carry the OIDC subject");
        // norskel-auth.user.default-role, applied by createFromOidc. Note this
        // is the *stored* role, independent of the roles the token carries.
        assertEquals("user", alice.getRole());
        assertEquals(net.norskel.auth.module.runtime.enums.UserTypeEnum.HUMAN,
                alice.getType(), "an OIDC login must never create a SERVICE row");
    }

    @Test
    void repeatedLoginsReuseTheSameUser() {
        UUID first = loginAndGetUserId();
        long countAfterFirst = userService.findAll().size();

        UUID second = loginAndGetUserId();
        UUID third = loginAndGetUserId();

        assertEquals(first, second, "upsertFromOidc must match on the OIDC subject");
        assertEquals(first, third);
        assertEquals(countAfterFirst, userService.findAll().size(),
                "repeated logins must not create duplicate users");
    }

    /**
     * Roles come from two independent places and are additive: Quarkus OIDC maps
     * the token's {@code groups} claim onto the identity, and the extension adds
     * the role stored on the user. Dev Services gives alice
     * {@code groups: [admin, user]}, so she reaches the admin endpoint even
     * though her stored role is only {@code user}.
     */
    @Test
    void tokenGroupsAndStoredRoleAreBothApplied() {
        given().header(bearer())
                .when().get("/reports/whoami")
                .then().statusCode(200)
                .body("roles", hasItem("admin"))   // from the token's groups claim
                .body("roles", hasItem("user"));   // stored on the user entity

        // Granted by the groups claim...
        given().header(bearer()).when().get("/reports/all").then().statusCode(200);
        // ...but nothing grants the machine-only role.
        given().header(bearer()).when().post("/reports/ingest").then().statusCode(403);
    }

    // --- endpoint backing the route-tester page ---

    /**
     * The page cannot exercise OIDC without this endpoint, and it is the only
     * thing that proves the password grant plus {@code openid} scope wiring in
     * {@link OidcTokenResource} works against a real provider.
     */
    @Test
    void oidcTokenEndpointMintsAUsableToken() {
        String token = given()
                .when().get("/example/oidc-token?user=alice")
                .then().statusCode(200)
                .body("access_token", notNullValue())
                .extract().path("access_token");

        given().header("Authorization", "Bearer " + token)
                .when().get("/reports/whoami")
                .then().statusCode(200)
                .body("authSource", equalTo("oidc"));
    }

    @Test
    void oidcTokenEndpointSupportsBobWhoIsNotAdmin() {
        String token = given()
                .when().get("/example/oidc-token?user=bob")
                .then().statusCode(200)
                .extract().path("access_token");
        Header bob = new Header("Authorization", "Bearer " + token);

        given().header(bob).when().get("/reports/whoami")
                .then().statusCode(200)
                .body("roles", hasItem("user"));
        // bob's groups claim has no admin, and his stored role is the default.
        given().header(bob).when().get("/reports/all").then().statusCode(403);
    }

    @Test
    void banningAnOidcUserBlocksTheirTokenImmediately() {
        UUID aliceId = loginAndGetUserId();

        // contentType is required even though these endpoints take no body:
        // UserResource declares @Consumes(APPLICATION_JSON) at class level, so a
        // bodyless POST with any other Content-Type is rejected with 415.
        given().header(apiKey()).contentType(ContentType.JSON)
                .when().post("/auth/users/" + aliceId + "/ban")
                .then().statusCode(204);

        // Same still-valid Keycloak token, now refused by the augmentor.
        given().header(bearer()).when().get("/reports/whoami").then().statusCode(401);

        given().header(apiKey()).contentType(ContentType.JSON)
                .when().post("/auth/users/" + aliceId + "/unban")
                .then().statusCode(204);

        given().header(bearer()).when().get("/reports/whoami").then().statusCode(200);
    }
}
