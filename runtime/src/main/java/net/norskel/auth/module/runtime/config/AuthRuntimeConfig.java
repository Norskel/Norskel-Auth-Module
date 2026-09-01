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
         * Ajoute les rôles portés par le token à l'identité de la requête.
         *
         * <p>À {@code false}, les rôles du fournisseur (claim {@link #rolesClaim()} et règles
         * {@code role-mapping}) ne sont plus accordés directement : ils servent uniquement à
         * décider du rôle stocké, via {@link #dbRoleFromSso()}. L'autorisation ne dépend alors
         * plus que du champ {@code role} de l'utilisateur, ce qui donne un jeu de rôles fermé,
         * indépendant du nommage des groupes côté IdP.
         *
         * <p>Sans {@link #dbRoleFromSso()}, mettre ce drapeau à {@code false} coupe toute
         * influence du SSO sur les rôles : chacun n'obtient que le rôle inscrit en base.
         */
        @WithDefault("true")
        boolean grantSsoRoles();

        /**
         * Rôles, par priorité décroissante, dont le SSO est maître en base.
         *
         * <p>À chaque login, si l'utilisateur détient l'un de ces rôles côté SSO (claim de rôles
         * ou règles {@code role-mapping}), il est écrit dans le champ {@code role} de l'utilisateur.
         * Le premier de la liste gagne : l'entité ne porte qu'un rôle, l'arbitrage entre plusieurs
         * rôles SSO doit donc être explicite et non dépendre de l'ordre des claims.
         *
         * <p>Le SSO est autoritaire dans les deux sens : perdre un rôle de cette liste côté SSO
         * ramène l'utilisateur à {@link #defaultRole()}, un privilège révoqué chez l'IdP ne devant
         * pas survivre en base. Un rôle absent de la liste n'est jamais touché : il a été attribué
         * à la main et ne relève pas du SSO.
         *
         * <p>Vide (défaut) : le rôle en base n'est plus jamais modifié après la création.
         *
         * <pre>
         * norskel-auth.user.db-role-from-sso=admin,manager
         * </pre>
         */
        Optional<List<String>> dbRoleFromSso();

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

