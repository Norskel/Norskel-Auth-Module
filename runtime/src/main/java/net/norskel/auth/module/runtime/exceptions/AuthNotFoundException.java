package net.norskel.auth.module.runtime.exceptions;

/**
 * AuthNotFoundException
 *
 * <p>Thrown when a user or API key does not exist. Extends
 * {@link java.util.NoSuchElementException} so that {@code UserStore} /
 * {@code ApiKeyStore} implementations throwing the plain JDK type stay
 * compatible; only this subtype is mapped to HTTP 404, leaving the host
 * application's own {@code NoSuchElementException} handling untouched.
 *
 * @author Norskel
 * @since 21.08.2026
 **/
public class AuthNotFoundException extends java.util.NoSuchElementException {

    public AuthNotFoundException(String message) {
        super(message);
    }
}
