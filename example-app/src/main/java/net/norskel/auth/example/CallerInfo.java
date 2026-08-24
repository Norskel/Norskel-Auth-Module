package net.norskel.auth.example;

import java.util.Set;

/**
 * What the application can learn about whoever made the request.
 *
 * <p>Note that {@code userId} and {@code email} are nullable: a service API key
 * authenticates a machine, not a person, so there is no user behind it.
 */
public record CallerInfo(
        String authSource,
        String userId,
        String email,
        String serviceName,
        Set<String> roles
) {}
