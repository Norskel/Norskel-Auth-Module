package net.norskel.auth.module.runtime;

import io.quarkus.oidc.runtime.OidcAuthenticationMechanism;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.AuthenticationRequest;
import io.quarkus.security.identity.request.TokenAuthenticationRequest;
import io.quarkus.smallrye.jwt.runtime.auth.JWTAuthMechanism;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.HttpCredentialTransport;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import lombok.extern.slf4j.Slf4j;
import net.norskel.auth.module.runtime.config.AuthBuildTimeConfig;
import net.norskel.auth.module.runtime.config.AuthRuntimeConfig;

import java.util.HashSet;
import java.util.Set;

/**
 * DualAuthMechanism
 *
 * @author Norskel
 * @since 30.03.2026
 **/

@Slf4j
@ApplicationScoped
public class DualAuthMechanism implements HttpAuthenticationMechanism {


    @Inject
    OidcAuthenticationMechanism oidcMechanism;

    @Inject
    JWTAuthMechanism jwtMechanism;

    @Inject
    AuthBuildTimeConfig config;

    @Override
    public Uni<SecurityIdentity> authenticate(RoutingContext context, IdentityProviderManager identityProviderManager) {

        String apiKey = context.request().getHeader(config.apiTokenHeader());

        if (apiKey != null && !apiKey.isBlank()) {
            log.info("[Auth] Authenticating with API key");
            return jwtMechanism.authenticate(context, identityProviderManager);
        }
        log.info("[Auth] Authenticating with OIDC");
        return oidcMechanism.authenticate(context, identityProviderManager);
    }

    @Override
    public Uni<ChallengeData> getChallenge(RoutingContext context) {
        return Uni.createFrom().item(
                new ChallengeData(401, "WWW-Authenticate", "Bearer, ApiKey")
        );
    }

    @Override
    public Set<Class<? extends AuthenticationRequest>> getCredentialTypes() {
        Set<Class<? extends AuthenticationRequest>> types = new HashSet<>();
        types.add(TokenAuthenticationRequest.class);
        types.addAll(oidcMechanism.getCredentialTypes());
        return types;
    }


    @Override
    public Uni<HttpCredentialTransport> getCredentialTransport(RoutingContext ctx) {
        // Indique à Quarkus que l'auth peut venir d'un header custom
        String header = config.apiTokenHeader();
        if (ctx.request().getHeader(header) != null) {
            return Uni.createFrom().item(new HttpCredentialTransport(
                    HttpCredentialTransport.Type.OTHER_HEADER, header));
        }
        return Uni.createFrom().item(new HttpCredentialTransport(
                HttpCredentialTransport.Type.AUTHORIZATION, "Bearer"));
    }

    @Override
    public int getPriority() {
        return 3000;
    }

}
