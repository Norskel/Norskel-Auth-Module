package net.norskel.auth.module.runtime;

/**
 * AuthAttributes
 *
 * <p>Names of the attributes this extension puts on the {@code SecurityIdentity},
 * and the values it uses for {@link #AUTH_SOURCE}. A service is a user row of
 * type {@code SERVICE}, so every augmented identity carries a {@link #USER_ID}:
 * application code that wants to tell machines from people must branch on
 * {@link #AUTH_SOURCE}, never on the absence of a user.
 *
 * @author Norskel
 * @since 21.08.2026
 **/
public final class AuthAttributes {

    /** Owning user id. Set on every identity this extension augments. */
    public static final String USER_ID = "user_id";

    /** The resolved {@code UserEntity}. Set on every identity this extension augments. */
    public static final String USER = "user";

    /** Which mechanism produced the identity; one of the {@code SOURCE_*} values. */
    public static final String AUTH_SOURCE = "auth_source";

    /** Service identity name. Present only for service API keys. */
    public static final String SERVICE_NAME = "service_name";

    public static final String SOURCE_OIDC = "oidc";
    public static final String SOURCE_API_KEY = "api-key";
    public static final String SOURCE_SERVICE_API_KEY = "service-api-key";

    private AuthAttributes() {
    }
}
