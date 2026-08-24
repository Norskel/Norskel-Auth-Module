package net.norskel.auth.module.runtime.mappers;

import jakarta.ws.rs.core.Response;
import net.norskel.auth.module.runtime.dto.ErrorResponse;
import net.norskel.auth.module.runtime.exceptions.AuthConflictException;
import net.norskel.auth.module.runtime.exceptions.AuthForbiddenException;
import net.norskel.auth.module.runtime.exceptions.AuthNotFoundException;
import net.norskel.auth.module.runtime.exceptions.AuthValidationException;
import org.jboss.resteasy.reactive.server.ServerExceptionMapper;

/**
 * AuthExceptionMappers
 *
 * <p>Maps the extension's own exceptions to HTTP status codes. Deliberately
 * scoped to the {@code net.norskel.auth.module.runtime.exceptions} types rather
 * than to {@link java.util.NoSuchElementException} and friends: a mapper for the
 * JDK types would be registered application-wide and would silently change how
 * the host application's unrelated failures are reported.
 *
 * @author Norskel
 * @since 21.08.2026
 **/
public class AuthExceptionMappers {

    @ServerExceptionMapper
    public Response notFound(AuthNotFoundException e) {
        return build(Response.Status.NOT_FOUND, "not_found", e.getMessage());
    }

    @ServerExceptionMapper
    public Response validation(AuthValidationException e) {
        return build(Response.Status.BAD_REQUEST, "invalid_request", e.getMessage());
    }

    @ServerExceptionMapper
    public Response conflict(AuthConflictException e) {
        return build(Response.Status.CONFLICT, "conflict", e.getMessage());
    }

    @ServerExceptionMapper
    public Response forbidden(AuthForbiddenException e) {
        return build(Response.Status.FORBIDDEN, "forbidden", e.getMessage());
    }

    private static Response build(Response.Status status, String error, String message) {
        return Response.status(status)
                .entity(new ErrorResponse(error, message))
                .build();
    }
}
