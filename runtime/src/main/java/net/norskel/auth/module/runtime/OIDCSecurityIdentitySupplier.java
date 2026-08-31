package net.norskel.auth.module.runtime;

import io.quarkus.oidc.UserInfo;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.json.JsonArray;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;
import lombok.extern.slf4j.Slf4j;
import net.norskel.auth.module.runtime.config.AuthRuntimeConfig;
import net.norskel.auth.module.runtime.entities.UserEntity;
import net.norskel.auth.module.runtime.enums.UserStateEnum;
import net.norskel.auth.module.runtime.roles.ClaimRoleResolver;
import net.norskel.auth.module.runtime.spi.UserService;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * OIDCSecurityIdentitySupplier
 *
 * <p>Stateless: the identity to augment is passed in per call, so a single
 * application-scoped instance is shared across requests.
 *
 * @author Norskel
 * @since 30.03.2026
 **/
@ApplicationScoped
@Slf4j
public class OIDCSecurityIdentitySupplier {

    @Inject
    UserService userService;

    @Inject
    AuthRuntimeConfig config;

    @Inject
    ClaimRoleResolver claimRoleResolver;

    public SecurityIdentity augment(SecurityIdentity identity) {
        // 1. Récupérer les infos utilisateur depuis l'introspection OIDC
        UserInfo userInfo = identity.getAttribute("userinfo");
        if (userInfo == null) {
            log.warn("[OIDC] No userinfo attribute on identity — userinfo required?");
            throw new AuthenticationFailedException("Missing userinfo from OIDC provider");
        }

        String subjectClaim = config.user().subjectClaim();
        String subject = userInfo.getString(subjectClaim);
        if (subject == null || subject.isBlank()) {
            log.warn("[OIDC] Missing '{}' claim in userinfo", subjectClaim);
            throw new AuthenticationFailedException("Missing subject claim");
        }

        String email = resolveEmail(userInfo);
        String name = firstNonBlank(
                userInfo.getString("preferred_username"),
                userInfo.getString("nickname"),
                userInfo.getString("name"),
                email);
        String avatarUrl = resolveAvatar(userInfo);

        log.debug("[OIDC] Resolving user sub={} email={}", subject, email);

        // 2. Upsert en base
        UserEntity user;
        try {
            user = userService.upsertFromOidc(subject, email, name, avatarUrl);
        } catch (Exception e) {
            log.error("[OIDC] Failed to upsert user from OIDC", e);
            throw new AuthenticationFailedException("User sync failed", e);
        }

        // 3. Vérifier l'état
        if (user.getState() == UserStateEnum.BLOCKED) {
            log.warn("[OIDC] Rejected banned user sub={} userId={}",
                    subject, user.getId());
            throw new AuthenticationFailedException("User is banned");
        }

        // 4. Mise à jour optionnelle du lastLogin (avec throttle)
        userService.updateLastLogin(user);

        // 5. Construire l'identité enrichie
        String role = user.getRole() != null
                ? user.getRole()
                : config.user().defaultRole();

        QuarkusSecurityIdentity.Builder builder = QuarkusSecurityIdentity.builder(identity)
                .addRole(role)
                .addAttribute(AuthAttributes.USER_ID, user.getId())
                .addAttribute(AuthAttributes.USER, user)
                .addAttribute(AuthAttributes.AUTH_SOURCE, AuthAttributes.SOURCE_OIDC);

        // Rôles additionnels issus du token (claim configurable)
        resolveRoles(userInfo).forEach(builder::addRole);

        // Rôles issus des règles nommées role-mapping. Plus riche que le claim ci-dessus, qui
        // suppose un claim contenant déjà des noms de rôles : ici on mappe la valeur d'un claim
        // quelconque, avec un filtrage de portée. Sans règle déclarée, ne renvoie rien.
        claimRoleResolver.rolesFor(userInfo).forEach(builder::addRole);

        return builder.build();
    }

    /** First non-blank value among the configured email claims. */
    private String resolveEmail(UserInfo userInfo) {
        return firstClaim(userInfo, config.user().emailClaims());
    }

    /**
     * First non-blank value among the configured avatar claims.
     *
     * <p>{@code null} when the provider sends none: an absent claim leaves the
     * stored avatar alone rather than clearing it.
     */
    private String resolveAvatar(UserInfo userInfo) {
        return firstClaim(userInfo, config.user().avatarClaims());
    }

    /** First non-blank string claim among {@code claims}, {@code null} if none. */
    private static String firstClaim(UserInfo userInfo, List<String> claims) {
        for (String claim : claims) {
            String value = safeString(userInfo, claim.trim());
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    /**
     * {@code getString} without the throw: a provider may send a claim as an
     * object (a nested {@code picture}, say), and that must not fail the login.
     */
    private static String safeString(UserInfo userInfo, String claim) {
        try {
            return userInfo.getString(claim);
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Roles read from the optional configured roles claim (array or delimited string). */
    private List<String> resolveRoles(UserInfo userInfo) {
        Optional<String> rolesClaim = config.user().rolesClaim();
        if (rolesClaim.isEmpty()) {
            return List.of();
        }
        String claim = rolesClaim.get();
        if (!userInfo.contains(claim)) {
            return List.of();
        }

        List<String> roles = new ArrayList<>();
        JsonArray array = safeArray(userInfo, claim);
        if (array != null) {
            for (JsonValue value : array) {
                if (value instanceof JsonString s) {
                    roles.add(s.getString());
                } else {
                    roles.add(value.toString());
                }
            }
        } else {
            String single = userInfo.getString(claim);
            if (single != null && !single.isBlank()) {
                for (String r : single.split("[,\\s]+")) {
                    if (!r.isBlank()) roles.add(r);
                }
            }
        }
        return roles;
    }

    private static JsonArray safeArray(UserInfo userInfo, String claim) {
        try {
            return userInfo.getArray(claim);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String firstNonBlank(String... values) {
        for (String v : values) {
            if (v != null && !v.isBlank()) return v;
        }
        return null;
    }
}
