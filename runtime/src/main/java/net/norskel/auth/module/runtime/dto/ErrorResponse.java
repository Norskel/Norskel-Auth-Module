package net.norskel.auth.module.runtime.dto;

/**
 * ErrorResponse
 *
 * @author Norskel
 * @since 21.08.2026
 **/
public record ErrorResponse(
        String error,
        String message
) {}
