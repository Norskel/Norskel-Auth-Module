package net.norskel.auth.module.runtime.resources;

import io.quarkus.security.Authenticated;
import io.quarkus.security.UnauthorizedException;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import net.norskel.auth.module.runtime.AuthAttributes;
import net.norskel.auth.module.runtime.dto.CreateApiKeyRequest;
import net.norskel.auth.module.runtime.dto.CreateApiKeyResponse;
import net.norskel.auth.module.runtime.dto.CreateServiceApiKeyRequest;
import net.norskel.auth.module.runtime.exceptions.AuthForbiddenException;
import net.norskel.auth.module.runtime.entities.ApiKeyEntity;
import net.norskel.auth.module.runtime.spi.ApiKeyService;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

/**
 * ApiKeyResource
 *
 * @author Norskel
 * @since 17.04.2026
 **/
@Path("/auth/api-keys")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class ApiKeyResource {

    @Inject
    ApiKeyService apiKeyService;
    @Inject
    SecurityIdentity identity;

    // === Me ===

    @GET
    @Path("/me")
    @Authenticated
    public List<ApiKeyEntity> listMine() {
        return apiKeyService.listByUser(currentUserId());
    }

    @POST
    @Path("/me")
    @Authenticated
    public CreateApiKeyResponse createMine(CreateApiKeyRequest req) {
        rejectServiceSelfMutation();
        if (req.name() == null || req.name().isBlank()) {
            throw new BadRequestException("name is required");
        }
        if (req.lifetimeDays() != null && req.lifetimeDays() <= 0) {
            throw new BadRequestException("lifetimeDays must be > 0");
        }
        Duration lifetime = req.lifetimeDays() != null
                ? Duration.ofDays(req.lifetimeDays())
                : null;
        // Self-issued: owner and creator are the same identity.
        ApiKeyService.IssuedApiKey issued =
                apiKeyService.create(currentUserId(), req.name(), lifetime, currentUserId());
        ApiKeyEntity created = issued.apiKey();
        return new CreateApiKeyResponse(created.getId(), created.getName(),
                issued.token(), created.getExpiresAt());
    }

    @DELETE
    @Path("/me/{id}")
    @Authenticated
    public Response revokeMine(@PathParam("id") UUID id) {
        rejectServiceSelfMutation();
        apiKeyService.revoke(id, currentUserId());
        return Response.noContent().build();
    }

    @DELETE
    @Path("/me")
    @Authenticated
    public Response revokeAllMine() {
        rejectServiceSelfMutation();
        apiKeyService.revokeAllForUser(currentUserId());
        return Response.noContent().build();
    }

    // === Admin ===

    @GET
    @Path("/users/{userId}")
    @RolesAllowed("admin")
    public List<ApiKeyEntity> listForUser(@PathParam("userId") UUID userId) {
        return apiKeyService.listByUser(userId);
    }

    @GET
    @Path("/{id}")
    @RolesAllowed("admin")
    public ApiKeyEntity getById(@PathParam("id") UUID id) {
        return apiKeyService.getApiKey(id);
    }

    @DELETE
    @Path("/{id}")
    @RolesAllowed("admin")
    public Response revokeAny(@PathParam("id") UUID id) {
        apiKeyService.revokeAsAdmin(id);
        return Response.noContent().build();
    }

    // === Service keys ===

    @GET
    @Path("/service")
    @RolesAllowed("admin")
    public List<ApiKeyEntity> listService() {
        return apiKeyService.listServiceKeys();
    }

    @POST
    @Path("/service")
    @RolesAllowed("admin")
    public CreateApiKeyResponse createService(CreateServiceApiKeyRequest req) {
        if (req.serviceName() == null || req.serviceName().isBlank()) {
            throw new BadRequestException("serviceName is required");
        }
        if (req.name() == null || req.name().isBlank()) {
            throw new BadRequestException("name is required");
        }
        if (req.role() == null || req.role().isBlank()) {
            throw new BadRequestException("role is required");
        }
        if (req.lifetimeDays() != null && req.lifetimeDays() <= 0) {
            throw new BadRequestException("lifetimeDays must be > 0");
        }
        Duration lifetime = req.lifetimeDays() != null
                ? Duration.ofDays(req.lifetimeDays())
                : null;
        // Records which admin stood up this service, so a departing admin's
        // leftovers can be found later.
        ApiKeyService.IssuedApiKey issued = apiKeyService.createServiceKey(
                req.serviceName(), req.name(), req.role(), lifetime, currentUserId());
        ApiKeyEntity created = issued.apiKey();
        return new CreateApiKeyResponse(created.getId(), created.getName(),
                issued.token(), created.getExpiresAt());
    }

    @DELETE
    @Path("/users/{userId}")
    @RolesAllowed("admin")
    public Response revokeAllForUser(@PathParam("userId") UUID userId) {
        apiKeyService.revokeAllForUser(userId);
        return Response.noContent().build();
    }

    // === Helper ===

    /**
     * The caller's user id, as put on the identity by {@code UserRoleAugmentor}.
     *
     * <p>{@code @Authenticated} only guarantees <em>some</em> mechanism accepted
     * the request; if the host application authenticates by a means this
     * extension does not augment, the attribute is absent and there is no
     * auth-module user to act on. That is a 401, not a 500.
     */
    private UUID currentUserId() {
        UUID userId = identity.getAttribute(AuthAttributes.USER_ID);
        if (userId != null) {
            return userId;
        }
        throw new UnauthorizedException("Request carries no auth-module identity");
    }

    /**
     * Refuses self-mutation by a service identity.
     *
     * <p>A service now has a real user row, so it can legitimately <em>read</em>
     * "me". Letting it write would mean a leaked service key could rename the
     * service or mint itself a fresh long-lived key, outliving revocation of the
     * key that was actually leaked. Services are therefore read-only on the
     * {@code /me} endpoints.
     */
    private void rejectServiceSelfMutation() {
        if (AuthAttributes.SOURCE_SERVICE_API_KEY
                .equals(identity.getAttribute(AuthAttributes.AUTH_SOURCE))) {
            throw new AuthForbiddenException(
                    "Service identities are read-only on /me endpoints; use the "
                            + "admin endpoints to manage a service");
        }
    }

}