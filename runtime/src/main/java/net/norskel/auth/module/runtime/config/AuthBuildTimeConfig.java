package net.norskel.auth.module.runtime.config;

import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

/**
 * AuthBuildTimeConfig
 *
 * @author Norskel
 * @since 17.04.2026
 **/
@ConfigMapping(prefix = "norskel-auth-build")
@ConfigRoot(phase = ConfigPhase.BUILD_AND_RUN_TIME_FIXED)
public interface AuthBuildTimeConfig {

    /** HTTP header carrying the API token. */
    @WithDefault("X-Api-Key")
    String apiTokenHeader();

    /** JWT issuer for signed API tokens. */
    @WithDefault("norskel-auth")
    String apiTokenIssuer();

    /**
     * Whether the {@code /auth/users} and {@code /auth/api-keys} endpoints are served.
     * Read at build time by {@code @EndpointDisabled} on the resources; set it to {@code false}
     * when the host application exposes its own user and API-key endpoints over the services.
     */
    @WithDefault("true")
    boolean restEnabled();
}
