package net.norskel.auth.module.runtime.resources;

import io.quarkus.security.Authenticated;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import net.norskel.auth.module.runtime.dto.CreateApiKeyRequest;
import net.norskel.auth.module.runtime.dto.CreateApiKeyResponse;
import net.norskel.auth.module.runtime.entities.ApiKeyEntity;
import net.norskel.auth.module.runtime.spi.ApiKeyService;
import net.norskel.auth.module.runtime.spi.UserService;

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
    UserService userService;
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
        if (req.name() == null || req.name().isBlank()) {
            throw new BadRequestException("name is required");
        }
        if (req.lifetimeDays() <= 0) {
            throw new BadRequestException("lifetimeDays must be > 0");
        }
        UUID userId = currentUserId();
        String token = apiKeyService.create(userId, req.name(), req.lifetimeDays());
        ApiKeyEntity created = apiKeyService.listByUser(userId).stream()
                .filter(k -> req.name().equals(k.getName()) && !Boolean.TRUE.equals(k.getRevoked()))
                .max((a, b) -> a.getCreatedAt().compareTo(b.getCreatedAt()))
                .orElseThrow();
        return new CreateApiKeyResponse(created.getId(), created.getName(),
                token, created.getExpiresAt());
    }

    @DELETE
    @Path("/me/{id}")
    @Authenticated
    public Response revokeMine(@PathParam("id") UUID id) {
        apiKeyService.revoke(id, currentUserId());
        return Response.noContent().build();
    }

    @DELETE
    @Path("/me")
    @Authenticated
    public Response revokeAllMine() {
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
        ApiKeyEntity key = apiKeyService.getApiKey(id);
        apiKeyService.revoke(id, key.getUserId());
        return Response.noContent().build();
    }

    @DELETE
    @Path("/users/{userId}")
    @RolesAllowed("admin")
    public Response revokeAllForUser(@PathParam("userId") UUID userId) {
        apiKeyService.revokeAllForUser(userId);
        return Response.noContent().build();
    }

    // === Helper ===

    private UUID currentUserId() {
        return userService.findById(identity.getAttribute("user_id")).getId();
    }

}