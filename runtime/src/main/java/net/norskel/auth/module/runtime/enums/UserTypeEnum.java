package net.norskel.auth.module.runtime.enums;

/**
 * What kind of caller a {@code UserEntity} represents.
 *
 * <p>A service is an ordinary user row with no OIDC subject and no email. That
 * is deliberate: it means service identities reuse the user lifecycle wholesale
 * — {@code banUser} disables every key at once, the role lives on the identity
 * rather than being copied onto each key, and name uniqueness is the existing
 * username check. No parallel entity, store or SPI is needed.
 */
public enum UserTypeEnum {

    /** A person, authenticated through OIDC and optionally holding API keys. */
    HUMAN,

    /** A machine caller, authenticated only by API key. */
    SERVICE
}
