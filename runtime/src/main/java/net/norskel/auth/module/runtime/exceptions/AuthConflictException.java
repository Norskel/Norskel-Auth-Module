package net.norskel.auth.module.runtime.exceptions;

/**
 * AuthConflictException
 *
 * <p>Thrown when an operation conflicts with existing state (duplicate user,
 * key for a banned user). Extends {@link IllegalStateException} so store
 * implementations throwing the plain JDK type stay compatible; only this
 * subtype is mapped to HTTP 409.
 *
 * @author Norskel
 * @since 21.08.2026
 **/
public class AuthConflictException extends IllegalStateException {

    public AuthConflictException(String message) {
        super(message);
    }
}
