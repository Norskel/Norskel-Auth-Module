package net.norskel.auth.module.runtime.dto;

/**
 * CreateApiKeyRequest
 *
 * @author Norskel
 * @since 17.04.2026
 **/
public record CreateApiKeyRequest(
        String name,
        String role,
        int lifetimeDays
) {}