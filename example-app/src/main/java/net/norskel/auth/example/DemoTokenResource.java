package net.norskel.auth.example;

import jakarta.annotation.security.PermitAll;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import java.util.Map;

/**
 * Hands the seeded demo credentials to the route-tester page so it works without
 * copy-pasting from the startup log.
 *
 * <p><strong>This is a sample-only pattern.</strong> An unauthenticated endpoint
 * that returns API keys would be a serious vulnerability in a real application.
 * It is gated on {@code example.seed.enabled} — the same flag that decides
 * whether demo credentials are created and logged at all — so switching that off
 * removes both the demo keys and this endpoint. Do not copy this class.
 */
@Path("/example/demo-tokens")
@Produces(MediaType.APPLICATION_JSON)
public class DemoTokenResource {

    @Inject
    ExampleBootstrap bootstrap;

    @GET
    @PermitAll
    public Map<String, String> tokens() {
        String userToken = bootstrap.userToken();
        if (userToken == null) {
            // Seeding disabled: there are no demo credentials to hand out.
            throw new NotFoundException("Demo seeding is disabled");
        }
        return Map.of(
                "userKey", userToken,
                "serviceKey", bootstrap.serviceToken(),
                "adminUserId", bootstrap.adminUserId());
    }
}
