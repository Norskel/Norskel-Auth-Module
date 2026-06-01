package net.norskel.auth.module.runtime.dto;

/**
 * UpdateUserRequest
 *
 * @author Norskel
 * @since 17.04.2026
 **/
public record UpdateUserRequest(
        String username,
        String name,
        String email,
        String avatarUrl,
        String role
) {}