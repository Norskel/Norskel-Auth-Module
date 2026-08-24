package net.norskel.auth.module.runtime.exceptions;

/**
 * AuthValidationException
 *
 * <p>Thrown when caller-supplied input is rejected (missing name, non-positive
 * lifetime). Extends {@link IllegalArgumentException} so callers catching the
 * plain JDK type stay compatible; only this subtype is mapped to HTTP 400.
 *
 * @author Norskel
 * @since 21.08.2026
 **/
public class AuthValidationException extends IllegalArgumentException {

    public AuthValidationException(String message) {
        super(message);
    }
}
