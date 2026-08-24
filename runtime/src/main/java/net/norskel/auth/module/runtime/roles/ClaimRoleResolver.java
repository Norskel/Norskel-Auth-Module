package net.norskel.auth.module.runtime.roles;

import io.quarkus.oidc.UserInfo;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import lombok.extern.slf4j.Slf4j;
import net.norskel.auth.module.runtime.config.AuthRuntimeConfig;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * ClaimRoleResolver
 *
 * <p>Applies the named rules of {@link AuthRuntimeConfig.RoleMappingConfig} to a userinfo
 * document.
 *
 * <p>Every rule is evaluated and the results are combined. Combining rather than picking the
 * first match matters when a provider publishes one claim per permission level: each such claim
 * lists only the entities held at exactly that level, so someone at the top level is absent from
 * the claim below. Reading a single rule would silently exclude them.
 *
 * @author Norskel
 * @since 24.08.2026
 **/
@ApplicationScoped
@Slf4j
public class ClaimRoleResolver {

    @Inject
    AuthRuntimeConfig config;

    /**
     * @param userInfo the userinfo document
     * @return the roles granted, empty when no rule is declared or none matched
     */
    public Set<String> rolesFor(UserInfo userInfo) {
        Map<String, AuthRuntimeConfig.RoleMappingConfig> rules = config.roleMapping();
        if (rules.isEmpty()) {
            return Set.of();
        }

        Set<String> roles = new LinkedHashSet<>();
        rules.forEach((name, rule) -> {
            if (matches(userInfo, rule)) {
                roles.addAll(rule.roles());
            }
        });

        if (roles.isEmpty()) {
            // Worth a line: an authenticated person with no mapped role will meet 403s
            // everywhere, and the cause is a rule that matched nothing rather than a bug.
            log.info("[Roles] No role mapped from {} rule(s)", rules.size());
        }
        return roles;
    }

    private boolean matches(UserInfo userInfo, AuthRuntimeConfig.RoleMappingConfig rule) {
        Set<String> values = ClaimValues.of(userInfo, rule.claim());
        if (values.isEmpty()) {
            return false;
        }

        List<String> exact = rule.values().orElse(null);
        return values.stream()
                .filter(value -> ClaimValues.isWithin(value, rule.valuePrefix(),
                        rule.hierarchySeparator()))
                // Both filters have to hold when both are configured, so a rule can name one
                // entity inside a wider scope.
                .anyMatch(value -> exact == null || exact.contains(value));
    }
}
