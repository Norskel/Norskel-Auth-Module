package net.norskel.auth.example;

import io.quarkus.security.Authenticated;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import net.norskel.auth.module.runtime.AuthAttributes;
import net.norskel.auth.module.runtime.entities.UserEntity;

import java.util.UUID;

/**
 * Business endpoints showing how to consume the identity the extension builds.
 *
 * <p>The extension produces three kinds of authenticated identity — an OIDC
 * user, a user API key, and a service API key — and this resource shows the one
 * thing that actually differs between them: a service key carries no user.
 */
@Path("/reports")
@Produces(MediaType.APPLICATION_JSON)
public class ReportResource {

    @Inject
    SecurityIdentity identity;

    /**
     * Works for any authenticated caller, human or machine.
     *
     * <p>This is the pattern to copy: branch on {@code auth_source} and treat
     * the user attributes as optional. Reading {@code user_id} unconditionally
     * is the most common mistake once service keys are in play.
     */
    @GET
    @Path("/whoami")
    @Authenticated
    public CallerInfo whoami() {
        String source = identity.getAttribute(AuthAttributes.AUTH_SOURCE);
        UUID userId = identity.getAttribute(AuthAttributes.USER_ID);
        UserEntity user = identity.getAttribute(AuthAttributes.USER);

        return new CallerInfo(
                source,
                userId != null ? userId.toString() : null,
                user != null ? user.getEmail() : null,
                identity.getAttribute(AuthAttributes.SERVICE_NAME),
                identity.getRoles());
    }

    /**
     * Needs a person behind the request.
     *
     * <p>Note what this does <em>not</em> test: a service identity has a real
     * user row, so {@code user != null} would happily let a machine through.
     * The question "is there a human here?" is answered by
     * {@link AuthAttributes#AUTH_SOURCE}, which is why application code should
     * branch on that rather than on the presence of a user.
     */
    @GET
    @Path("/mine")
    @Authenticated
    public String mine() {
        if (AuthAttributes.SOURCE_SERVICE_API_KEY
                .equals(identity.getAttribute(AuthAttributes.AUTH_SOURCE))) {
            throw new jakarta.ws.rs.ForbiddenException(
                    "This endpoint is for people; " + identity.getPrincipal().getName()
                            + " is a service identity");
        }
        UserEntity user = identity.getAttribute(AuthAttributes.USER);
        return "{\"report\":\"personal report for " + user.getUsername() + "\"}";
    }

    /**
     * Machine-to-machine entry point. Guarded by a dedicated role rather than
     * {@code admin}, so the service key that calls it cannot also administer
     * users or mint further keys.
     */
    @POST
    @Path("/ingest")
    @RolesAllowed("report-ingest")
    public String ingest() {
        String service = identity.getAttribute(AuthAttributes.SERVICE_NAME);
        return "{\"ingested\":true,\"by\":\"" + (service != null ? service : "user") + "\"}";
    }

    /** Human administration, reachable by an OIDC user or a user API key. */
    @GET
    @Path("/all")
    @RolesAllowed("admin")
    public String all() {
        return "{\"report\":\"everything\"}";
    }
}
