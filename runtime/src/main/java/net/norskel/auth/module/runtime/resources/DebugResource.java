package net.norskel.auth.module.runtime.resources;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import net.norskel.auth.module.runtime.entities.UserEntity;
import net.norskel.auth.module.runtime.spi.ApiKeyService;
import net.norskel.auth.module.runtime.spi.UserService;

import java.util.UUID;

/**
 * ApiKeyResource
 *
 * @author Norskel
 * @since 17.04.2026
 **/
@Path("/api/auth/debug")
public class DebugResource {

    @Inject
    ApiKeyService apiKeyService;

    @Inject
    UserService userService;

    @GET
    @Path("/user")
    public UserEntity createUser() {
        return this.userService.create(UserEntity.builder().id(UUID.randomUUID()).username("test").email("test").build());
    }

    @GET
    @Path("/key/{userId}")
    public String createApiKey(@PathParam("userId") UUID userId) {
        return this.apiKeyService.create(userId, "test", 1);
    }
}
