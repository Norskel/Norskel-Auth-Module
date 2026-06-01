package net.norskel.auth.module.runtime.dto;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * CreateApiKeyResponse
 *
 * @author Norskel
 * @since 17.04.2026
 **/
public record CreateApiKeyResponse(
        UUID id,
        String name,
        String token,
        OffsetDateTime expiresAt
) {}