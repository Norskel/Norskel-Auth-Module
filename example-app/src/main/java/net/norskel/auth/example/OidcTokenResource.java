package net.norskel.auth.example;

import jakarta.annotation.security.PermitAll;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;

/**
 * Mints a real OIDC access token so the route-tester page can exercise the OIDC
 * half of the extension, not just API keys.
 *
 * <p>Performs a password grant against whichever provider {@code quarkus.oidc}
 * is pointed at — in dev and test that is the Keycloak started by Dev Services.
 * The {@code openid} scope is requested explicitly: the extension requires
 * {@code user-info-required=true}, and Keycloak refuses {@code /userinfo} for a
 * token without it, which the application reports as an unexplained 401.
 *
 * <p><strong>Sample-only, like {@link DemoTokenResource}.</strong> An
 * unauthenticated endpoint that performs a password grant and returns the token
 * has no place in a real application. It is gated on
 * {@code example.seed.enabled}. Do not copy this class.
 */
@Path("/example/oidc-token")
@Produces(MediaType.APPLICATION_JSON)
public class OidcTokenResource {

    private final HttpClient http = HttpClient.newHttpClient();

    @ConfigProperty(name = "example.seed.enabled", defaultValue = "true")
    boolean seedEnabled;

    /** Absent unless an OIDC provider is configured or Dev Services supplied one. */
    @ConfigProperty(name = "quarkus.oidc.auth-server-url")
    Optional<String> authServerUrl;

    @ConfigProperty(name = "quarkus.oidc.client-id", defaultValue = "quarkus-app")
    String clientId;

    @ConfigProperty(name = "quarkus.oidc.credentials.secret", defaultValue = "secret")
    String clientSecret;

    @GET
    @PermitAll
    public Response token(@QueryParam("user") String user) {
        if (!seedEnabled) {
            return problem(Response.Status.NOT_FOUND, "Demo seeding is disabled");
        }
        if (authServerUrl.isEmpty()) {
            return problem(Response.Status.SERVICE_UNAVAILABLE,
                    "No OIDC provider configured.");
        }

        String username = (user == null || user.isBlank()) ? "alice" : user.trim();
        // Dev Services seeds alice and bob with password == username.
        String form = "grant_type=password"
                + "&username=" + enc(username)
                + "&password=" + enc(username)
                + "&client_id=" + enc(clientId)
                + "&client_secret=" + enc(clientSecret)
                + "&scope=openid";

        try {
            HttpRequest req = HttpRequest.newBuilder(
                            URI.create(authServerUrl.get() + "/protocol/openid-connect/token"))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(form))
                    .build();
            HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());

            if (res.statusCode() != 200) {
                return problem(Response.Status.SERVICE_UNAVAILABLE,
                        "Token request rejected by the provider (HTTP "
                                + res.statusCode() + "): " + res.body());
            }
            // Pass the provider's response through untouched; the page reads
            // access_token from it.
            return Response.ok(res.body()).build();
        } catch (Exception e) {
            // The placeholder %prod URL is unreachable by design, so this is the
            // expected outcome when the packaged jar is run without an IDP.
            return problem(Response.Status.SERVICE_UNAVAILABLE,
                    "Could not reach the OIDC provider at " + authServerUrl.get()
                            + " (" + e.getClass().getSimpleName() + "). In prod mode this is"
                            + " expected: Dev Services only runs under quarkus:dev or tests.");
        }
    }

    private static Response problem(Response.Status status, String message) {
        return Response.status(status)
                .entity(Map.of("error", "oidc_unavailable", "message", message))
                .build();
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}
