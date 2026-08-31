package net.norskel.auth.module.runtime.roles;

import io.quarkus.oidc.UserInfo;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import net.norskel.auth.module.runtime.config.AuthRuntimeConfig;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ClaimRoleResolverTest {

    /**
     * A hand-written rule rather than a mock: the resolver reads five accessors per rule, and
     * stubbing each would say more about the mocking library than about the mapping.
     */
    private static AuthRuntimeConfig.RoleMappingConfig rule(String claim,
                                                            List<String> roles,
                                                            String valuePrefix,
                                                            List<String> values) {
        return new AuthRuntimeConfig.RoleMappingConfig() {
            @Override
            public String claim() {
                return claim;
            }

            @Override
            public List<String> roles() {
                return roles;
            }

            @Override
            public Optional<String> valuePrefix() {
                return Optional.ofNullable(valuePrefix);
            }

            @Override
            public Optional<List<String>> values() {
                return Optional.ofNullable(values);
            }

            @Override
            public String hierarchySeparator() {
                return "/";
            }
        };
    }

    private static ClaimRoleResolver resolver(
            Map<String, AuthRuntimeConfig.RoleMappingConfig> rules) {
        ClaimRoleResolver resolver = new ClaimRoleResolver();
        resolver.config = new AuthRuntimeConfig() {
            @Override
            public ApiTokenRuntimeConfig apiToken() {
                throw new UnsupportedOperationException("not used by the resolver");
            }

            @Override
            public UserRuntimeConfig user() {
                throw new UnsupportedOperationException("not used by the resolver");
            }

            @Override
            public Map<String, RoleMappingConfig> roleMapping() {
                return rules;
            }
        };
        return resolver;
    }

    /** A userinfo answering the given claims as arrays, and reporting the rest as absent. */
    private static UserInfo userInfo(Map<String, List<String>> claims) {
        UserInfo userInfo = mock(UserInfo.class);
        lenient().when(userInfo.contains(org.mockito.ArgumentMatchers.anyString()))
                .thenReturn(false);
        claims.forEach((claim, values) -> {
            JsonArray array = values.stream()
                    .collect(Json::createArrayBuilder,
                            jakarta.json.JsonArrayBuilder::add,
                            (a, b) -> {
                            })
                    .build();
            lenient().when(userInfo.contains(claim)).thenReturn(true);
            lenient().when(userInfo.getArray(claim)).thenReturn(array);
        });
        return userInfo;
    }

    private static Map<String, AuthRuntimeConfig.RoleMappingConfig> rules(
            Object... nameThenRule) {
        Map<String, AuthRuntimeConfig.RoleMappingConfig> map = new LinkedHashMap<>();
        for (int i = 0; i < nameThenRule.length; i += 2) {
            map.put((String) nameThenRule[i],
                    (AuthRuntimeConfig.RoleMappingConfig) nameThenRule[i + 1]);
        }
        return map;
    }

    @Test
    void rolesFor_grantsNothing_whenNoRuleIsDeclared() {
        ClaimRoleResolver resolver = resolver(Map.of());

        assertTrue(resolver.rolesFor(userInfo(Map.of("groups", List.of("platform")))).isEmpty());
    }

    @Test
    void rolesFor_grantsTheRoles_ofARuleWhoseClaimHoldsAValue() {
        ClaimRoleResolver resolver = resolver(rules(
                "owners", rule("claims/owner", List.of("admin", "user"), "platform", null)));

        Set<String> roles = resolver.rolesFor(
                userInfo(Map.of("claims/owner", List.of("platform", "platform/build"))));

        assertEquals(Set.of("admin", "user"), roles);
    }

    @Test
    void rolesFor_combinesEveryRule_ratherThanStoppingAtTheFirst() {
        // The trap this guards: a provider publishing one claim per permission level lists in
        // each only the entities held at exactly that level, so someone at the top is absent
        // from the level below. Reading a single rule would exclude them.
        ClaimRoleResolver resolver = resolver(rules(
                "owners", rule("claims/owner", List.of("admin"), "platform", null),
                "members", rule("claims/member", List.of("user"), "platform", null)));

        Set<String> both = resolver.rolesFor(userInfo(Map.of(
                "claims/owner", List.of("platform/build"),
                "claims/member", List.of("platform/deploy"))));
        Set<String> ownerOnly = resolver.rolesFor(userInfo(Map.of(
                "claims/owner", List.of("platform/build"),
                "claims/member", List.of())));

        assertEquals(Set.of("admin", "user"), both);
        assertEquals(Set.of("admin"), ownerOnly);
    }

    @Test
    void rolesFor_grantsNothing_whenTheClaimIsAbsent() {
        ClaimRoleResolver resolver = resolver(rules(
                "owners", rule("claims/owner", List.of("admin"), null, null)));

        assertTrue(resolver.rolesFor(userInfo(Map.of("other", List.of("x")))).isEmpty());
    }

    @Test
    void rolesFor_grantsNothing_whenTheClaimIsPresentButEmpty() {
        ClaimRoleResolver resolver = resolver(rules(
                "owners", rule("claims/owner", List.of("admin"), null, null)));

        assertTrue(resolver.rolesFor(userInfo(Map.of("claims/owner", List.of()))).isEmpty());
    }

    @Test
    void rolesFor_ignoresValues_outsideTheConfiguredPrefix() {
        ClaimRoleResolver resolver = resolver(rules(
                "owners", rule("claims/owner", List.of("admin"), "platform", null)));

        assertTrue(resolver.rolesFor(userInfo(Map.of(
                "claims/owner", List.of("other-team", "other-team/thing")))).isEmpty());
    }

    @Test
    void rolesFor_doesNotMatchANeighbour_whoseNameStartsWithThePrefix() {
        // "platform-archive" is a different entity; a plain startsWith would have let it in.
        ClaimRoleResolver resolver = resolver(rules(
                "owners", rule("claims/owner", List.of("admin"), "platform", null)));

        assertTrue(resolver.rolesFor(
                userInfo(Map.of("claims/owner", List.of("platform-archive")))).isEmpty());
    }

    @Test
    void rolesFor_considersEveryValue_whenNoPrefixIsConfigured() {
        ClaimRoleResolver resolver = resolver(rules(
                "any", rule("claims/owner", List.of("admin"), null, null)));

        assertEquals(Set.of("admin"),
                resolver.rolesFor(userInfo(Map.of("claims/owner", List.of("anything")))));
    }

    @Test
    void rolesFor_appliesAnExactValueList() {
        ClaimRoleResolver resolver = resolver(rules(
                "release", rule("groups", List.of("releases"), null,
                        List.of("platform/releasetracker"))));

        Set<String> matched = resolver.rolesFor(
                userInfo(Map.of("groups", List.of("platform/releasetracker"))));
        Set<String> other = resolver.rolesFor(
                userInfo(Map.of("groups", List.of("platform/something-else"))));

        assertEquals(Set.of("releases"), matched);
        assertTrue(other.isEmpty());
    }

    @Test
    void rolesFor_requiresBothFilters_whenPrefixAndValuesAreSet() {
        ClaimRoleResolver resolver = resolver(rules(
                "narrow", rule("groups", List.of("special"), "platform",
                        List.of("platform/build", "other/thing"))));

        // In the exact list but outside the prefix: refused.
        assertTrue(resolver.rolesFor(userInfo(Map.of("groups", List.of("other/thing")))).isEmpty());
        assertEquals(Set.of("special"),
                resolver.rolesFor(userInfo(Map.of("groups", List.of("platform/build")))));
    }

    @Test
    void of_readsAClaimHoldingADelimitedString() {
        UserInfo userInfo = mock(UserInfo.class);
        when(userInfo.contains("roles")).thenReturn(true);
        when(userInfo.getArray("roles")).thenThrow(new IllegalStateException("not an array"));
        when(userInfo.getString("roles")).thenReturn("admin, user");

        assertEquals(Set.of("admin", "user"), ClaimValues.of(userInfo, "roles"));
    }

    @Test
    void isWithin_isSegmentAware() {
        assertTrue(ClaimValues.isWithin("platform", Optional.of("platform"), "/"));
        assertTrue(ClaimValues.isWithin("platform/build", Optional.of("platform"), "/"));
        assertFalse(ClaimValues.isWithin("platform-archive", Optional.of("platform"), "/"));
        assertTrue(ClaimValues.isWithin("anything", Optional.empty(), "/"));
    }

    @Test
    void of_toleratesAnAbsentClaimAndANullUserInfo() {
        assertTrue(ClaimValues.of(null, "groups").isEmpty());
        assertTrue(ClaimValues.of(userInfo(Map.of()), "groups").isEmpty());
    }
}
