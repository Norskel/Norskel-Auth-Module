package net.norskel.auth.module.runtime.config;

import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

/**
 * AuthRuntimeConfig
 *
 * @author Norskel
 * @since 30.03.2026
 **/
@ConfigMapping(prefix = "norskel-auth")
@ConfigRoot(phase = ConfigPhase.RUN_TIME)
public interface AuthRuntimeConfig {

    /**
     * Configuration of the API token authentication mechanism.
     */
    ApiTokenRuntimeConfig apiToken();

    /**
     * Configuration related to user synchronization and claims mapping.
     */
    UserRuntimeConfig user();


    interface ApiTokenRuntimeConfig {
        /**
         * Durée de vie par défaut des tokens créés sans TTL explicite.
         * Format ISO-8601: PT24H, P30D, PT720H...
         * Vide = pas d'expiration par défaut.
         */
        Optional<Duration> defaultTtl();


        /**
         * Si true, le lastUsedAt est mis à jour à chaque requête.
         * Désactivable pour éviter une écriture DB par requête authentifiée.
         */
        @WithDefault("true")
        boolean trackUsage();

        /**
         * Throttle : fréquence minimale de mise à jour de lastUsedAt.
         * Évite de spammer la DB si trackUsage=true.
         */
        @WithDefault("PT1M")
        Duration usageUpdateThrottle();
    }

    interface UserRuntimeConfig {
        /**
         * Crée automatiquement un User au premier login OIDC.
         * Si false, un user inconnu est rejeté (401).
         */
        @WithDefault("true")
        boolean autoCreateOnOidc();

        /**
         * Rôles attribués par défaut aux nouveaux users OIDC.
         */
        @WithDefault("user")
        String defaultRole();


        /**
         * Claim JWT à lire pour récupérer les rôles de l'utilisateur.
         * Ex: "groups", "realm_access/roles" (Keycloak), "roles".
         * Si vide, seuls les defaultRoles s'appliquent.
         */
        Optional<String> rolesClaim();

        /**
         * Claim JWT à lire pour l'identifiant utilisateur.
         * Par défaut "sub" (standard OIDC).
         */
        @WithDefault("sub")
        String subjectClaim();

        /**
         * Ordre des claims à essayer pour l'email.
         * Premier claim non vide gagné.
         */
        @WithDefault("email,preferred_username")
        List<String> emailClaims();

        /**
         * Ordre des claims à essayer pour l'URL de l'avatar.
         * Premier claim non vide gagné.
         *
         * <p>{@code picture} est le claim standard OIDC ; {@code avatar_url} est
         * celui de GitLab/GitHub. Si aucun n'est présent, l'avatar reste inchangé.
         */
        @WithDefault("picture,avatar_url")
        List<String> avatarClaims();
    }
}

