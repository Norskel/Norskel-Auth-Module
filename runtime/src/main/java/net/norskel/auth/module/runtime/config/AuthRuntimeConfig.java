package net.norskel.auth.module.runtime.config;

import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

import java.time.Duration;
import java.util.List;
import java.util.Map;
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

    /**
     * Named rules granting roles from the value of a claim.
     */
    Map<String, RoleMappingConfig> roleMapping();


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
    }

    /**
     * One rule: "if this claim holds a value in scope, grant these roles".
     *
     * <p>Richer than {@link UserRuntimeConfig#rolesClaim()}, which assumes a single claim already
     * holding role names. Providers rarely do that. Some publish one claim per permission level,
     * so several rules are needed to cover them all; some publish hierarchical paths, where a
     * naive match would admit a neighbour whose name merely starts the same way.
     *
     * <p>Rules are named freely; the name only groups the keys together and never appears in the
     * granted roles. All rules are evaluated and their results combined with the roles already
     * granted, so declaring none changes nothing.
     *
     * <pre>
     * norskel-auth.role-mapping.owners.claim=https://example.org/claims/groups/owner
     * norskel-auth.role-mapping.owners.roles=admin,user
     * norskel-auth.role-mapping.owners.value-prefix=platform
     * </pre>
     */
    interface RoleMappingConfig {

        /**
         * The claim to read. Its value may be an array, or a string holding several values
         * separated by commas or whitespace.
         */
        String claim();

        /**
         * The roles granted when the claim holds at least one value in scope.
         */
        List<String> roles();

        /**
         * Restricts which values count, by prefix, one hierarchy segment at a time.
         *
         * <p>With {@code platform} and the default separator, the values {@code platform} and
         * {@code platform/build} count while {@code platform-archive} does not — the latter
         * being a different entity whose name merely starts the same way. A plain
         * {@code startsWith} would have admitted it.
         *
         * <p>Left empty, every value in the claim counts.
         */
        Optional<String> valuePrefix();

        /**
         * Restricts which values count, by exact match. Combined with a prefix, a value has to
         * satisfy both.
         *
         * <p>Left empty, no exact-match filtering is applied.
         */
        Optional<List<String>> values();

        /**
         * The separator marking hierarchy inside a claim value, used by {@link #valuePrefix()}.
         */
        @WithDefault("/")
        String hierarchySeparator();
    }
}

