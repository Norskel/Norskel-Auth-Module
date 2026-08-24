package net.norskel.auth.example;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.Header;
import jakarta.inject.Inject;
import net.norskel.auth.module.runtime.entities.UserEntity;
import net.norskel.auth.module.runtime.spi.ApiKeyService;
import net.norskel.auth.module.runtime.spi.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

/**
 * Exercises the example app as a real consumer of the extension.
 *
 * <p>This is the coverage the extension's own tests cannot provide: it proves
 * the extension behaves correctly when pulled in as a dependency by an outside
 * application, with that application's own resources and roles.
 */
@QuarkusTest
class ExampleAppTest {

    @Inject
    UserService userService;

    @Inject
    ApiKeyService apiKeyService;

    private String userKey;
    private String serviceKey;

    @BeforeEach
    void mintKeys() {
        // Distinct from what ExampleBootstrap seeds, so the two do not collide
        // on the unique username / service-name constraints.
        UserEntity user = userService.create(UserEntity.builder()
                .username("test-admin-" + System.nanoTime())
                .email("test@example.test")
                .role("admin")
                .oidcId("oidc-test-" + System.nanoTime())
                .build());
        userKey = apiKeyService
                .create(user.getId(), "test-user-key", Duration.ofDays(1)).token();
        serviceKey = apiKeyService
                .createServiceKey("test-collector-" + System.nanoTime(),
                        "test-service-key", "report-ingest", Duration.ofDays(1))
                .token();
    }

    private Header key(String token) {
        return new Header("X-Api-Key", token);
    }

    @Test
    void unauthenticatedRequestsAreRejected() {
        given().when().get("/reports/whoami").then().statusCode(401);
    }

    @Test
    void userKey_carriesAUserAndItsRole() {
        given().header(key(userKey))
                .when().get("/reports/whoami")
                .then().statusCode(200)
                .body("authSource", equalTo("api-key"))
                .body("email", equalTo("test@example.test"))
                .body("serviceName", nullValue())
                .body("roles", hasItem("admin"));
    }

    @Test
    void userKey_reachesUserAndAdminEndpoints() {
        given().header(key(userKey)).when().get("/reports/mine").then().statusCode(200);
        given().header(key(userKey)).when().get("/reports/all").then().statusCode(200);
    }

    @Test
    void userKey_isRefusedTheMachineOnlyEndpoint() {
        // The user has "admin", not "report-ingest": roles are not hierarchical.
        given().header(key(userKey)).when().post("/reports/ingest").then().statusCode(403);
    }

    @Test
    void serviceKey_carriesAServiceNameAndNoUser() {
        given().header(key(serviceKey))
                .when().get("/reports/whoami")
                .then().statusCode(200)
                .body("authSource", equalTo("service-api-key"))
                // A service is a user row, so it does carry a userId. What marks
                // it as a machine is authSource, not a missing user.
                .body("userId", notNullValue())
                .body("email", nullValue())
                .body("serviceName", notNullValue())
                .body("roles", hasItem("report-ingest"));
    }

    @Test
    void serviceKey_reachesTheMachineEndpointOnly() {
        given().header(key(serviceKey))
                .when().post("/reports/ingest")
                .then().statusCode(200)
                .body("ingested", is(true));

        // Refused because it is a machine, not because a user is missing.
        given().header(key(serviceKey)).when().get("/reports/mine").then().statusCode(403);
        // Deliberately not granted "admin".
        given().header(key(serviceKey)).when().get("/reports/all").then().statusCode(403);
    }

    @Test
    void serviceKey_mayReadItsOwnRecordButNotChangeIt() {
        // It has a real user row now, so reading "me" is meaningful.
        given().header(key(serviceKey))
                .when().get("/auth/users/me")
                .then().statusCode(200)
                .body("type", equalTo("SERVICE"))
                .body("oidc_id", nullValue());

        // Writing is refused, so a leaked service key cannot mint a successor
        // that would survive revoking the leaked one.
        given().header(key(serviceKey)).contentType(io.restassured.http.ContentType.JSON)
                .when().body("{\"name\":\"renamed\"}").put("/auth/users/me")
                .then().statusCode(403)
                .body("error", equalTo("forbidden"));

        given().header(key(serviceKey)).contentType(io.restassured.http.ContentType.JSON)
                .when().body("{\"name\":\"self\",\"lifetimeDays\":1}").post("/auth/api-keys/me")
                .then().statusCode(403);
    }

    @Test
    void banningTheServiceUserDisablesItsKeys() {
        String svcName = "kill-switch-" + System.nanoTime();
        var issued = apiKeyService.createServiceKey(svcName, "k", "report-ingest",
                java.time.Duration.ofDays(1));
        Header svc = new Header("X-Api-Key", issued.token());

        given().header(svc).when().post("/reports/ingest").then().statusCode(200);

        userService.banUser(issued.apiKey().getUserId());

        given().header(svc).when().post("/reports/ingest").then().statusCode(401);
    }

    @Test
    void extensionManagementEndpointsAreMountedInTheHostApp() {
        given().header(key(userKey)).when().get("/auth/users").then().statusCode(200);
        given().header(key(userKey)).when().get("/auth/api-keys/service").then().statusCode(200);
    }

    // --- route tester page ---

    @Test
    void routeTesterPageIsServed() {
        given().when().get("/")
                .then().statusCode(200)
                .body(org.hamcrest.Matchers.containsString("testeur de routes"));
    }

    @Test
    void demoTokensEndpointFeedsThePage() {
        // The page prefills itself from here; if this contract breaks the UI
        // silently loads with empty key fields.
        given().when().get("/example/demo-tokens")
                .then().statusCode(200)
                .body("userKey", org.hamcrest.Matchers.startsWith("ey"))
                .body("serviceKey", org.hamcrest.Matchers.startsWith("ey"))
                .body("adminUserId", org.hamcrest.Matchers.not(org.hamcrest.Matchers.emptyString()));
    }
}
