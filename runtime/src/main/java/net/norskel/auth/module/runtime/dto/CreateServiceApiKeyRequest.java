package net.norskel.auth.module.runtime.dto;

/**
 * CreateServiceApiKeyRequest
 *
 * @author Norskel
 * @since 21.08.2026
 **/
public record CreateServiceApiKeyRequest(
        String serviceName,
        String name,
        String role,
        Integer lifetimeDays
) {}
