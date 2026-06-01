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
    String apiTokenjwtIssuer();
}
