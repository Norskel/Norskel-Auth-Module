package net.norskel.auth.module.runtime.exceptions;

/**
 * AuthForbiddenException
 *
 * <p>Thrown when an authenticated caller acts on a resource they do not own.
 * Extends {@link SecurityException} so callers catching the plain JDK type
 * stay compatible; only this subtype is mapped to HTTP 403.
 *
 * @author Norskel
 * @since 21.08.2026
 **/
public class AuthForbiddenException extends SecurityException {

    public AuthForbiddenException(String message) {
        super(message);
    }
}
