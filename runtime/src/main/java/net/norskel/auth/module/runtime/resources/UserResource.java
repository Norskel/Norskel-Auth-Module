package net.norskel.auth.module.runtime.resources;

import io.quarkus.security.Authenticated;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import net.norskel.auth.module.runtime.dto.UpdateUserRequest;
import net.norskel.auth.module.runtime.entities.UserEntity;
import net.norskel.auth.module.runtime.spi.UserService;

import java.util.List;
import java.util.UUID;

/**
 * UserResource
 *
 * @author Norskel
 * @since 17.04.2026
 **/
@Path("/auth/users")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class UserResource {

    @Inject
    UserService userService;
    @Inject
    SecurityIdentity identity;

    // === Me ===

    @GET
    @Path("/me")
    @Authenticated
    public UserEntity me() {
        return currentUser();
    }

    @PUT
    @Path("/me")
    @Authenticated
    public UserEntity updateMe(UpdateUserRequest req) {
        UserEntity u = currentUser();
        applyUpdate(u, req, false);
        return userService.update(u);
    }

    // === Admin ===

    @GET
    @RolesAllowed("admin")
    public List<UserEntity> list() {
        return userService.findAll();
    }

    @GET
    @Path("/{id}")
    @RolesAllowed("admin")
    public UserEntity getById(@PathParam("id") UUID id) {
        return userService.findById(id);
    }

    @POST
    @RolesAllowed("admin")
    public Response create(@Valid UserEntity user) {
        UserEntity created = userService.create(user);
        return Response.status(Response.Status.CREATED).entity(created).build();
    }

    @PUT
    @Path("/{id}")
    @RolesAllowed("admin")
    public UserEntity update(@PathParam("id") UUID id, UpdateUserRequest req) {
        UserEntity u = userService.findById(id);
        applyUpdate(u, req, true);  // admin peut changer le role
        return userService.update(u);
    }

    @DELETE
    @Path("/{id}")
    @RolesAllowed("admin")
    public Response delete(@PathParam("id") UUID id) {
        userService.deleteById(id);
        return Response.noContent().build();
    }

    @POST
    @Path("/{id}/ban")
    @RolesAllowed("admin")
    public Response ban(@PathParam("id") UUID id) {
        userService.banUser(id);
        return Response.noContent().build();
    }

    @POST @Path("/{id}/unban") @RolesAllowed("admin")
    public Response unban(@PathParam("id") UUID id) {
        userService.unbanUser(id);
        return Response.noContent().build();
    }

    // === Helpers ===

    private UserEntity currentUser() {
        return userService.findById(identity.getAttribute("user_id"));
    }

    private void applyUpdate(UserEntity u, UpdateUserRequest req, boolean isAdmin) {
        if (req.username() != null) u.setUsername(req.username());
        if (req.name() != null) u.setName(req.name());
        if (req.email() != null) u.setEmail(req.email());
        if (req.avatarUrl() != null) u.setAvatarUrl(req.avatarUrl());
        if (isAdmin && req.role() != null) u.setRole(req.role());
    }
}