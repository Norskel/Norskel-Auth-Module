package net.norskel.auth.module.runtime.roles;

import io.quarkus.oidc.UserInfo;
import jakarta.json.JsonArray;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;

import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;

/**
 * ClaimValues
 *
 * <p>Reading the values of a claim, and deciding which of them are in scope.
 *
 * <p>Kept apart from the resolver so these rules — the part that is easy to get wrong — can be
 * tested without a security context.
 *
 * @author Norskel
 * @since 24.08.2026
 **/
public final class ClaimValues {

    private ClaimValues() {
    }

    /**
     * Reads a claim whose value is either an array or a string holding several values.
     *
     * @param userInfo the userinfo document
     * @param claim    the claim name
     * @return the values, in the order given, without duplicates; empty when the claim is absent
     */
    public static Set<String> of(UserInfo userInfo, String claim) {
        Set<String> values = new LinkedHashSet<>();
        if (userInfo == null || claim == null || !userInfo.contains(claim)) {
            return values;
        }

        JsonArray array = safeArray(userInfo, claim);
        if (array != null) {
            for (JsonValue value : array) {
                // Skip anything that is not a string rather than calling toString on it, which
                // would yield a quoted "\"team\"" and match no rule.
                if (value instanceof JsonString text) {
                    values.add(text.getString());
                }
            }
            return values;
        }

        String single = userInfo.getString(claim);
        if (single != null && !single.isBlank()) {
            for (String part : single.split("[,\\s]+")) {
                if (!part.isBlank()) {
                    values.add(part);
                }
            }
        }
        return values;
    }

    /**
     * @param value     a claim value, possibly hierarchical
     * @param prefix    the configured prefix, if any
     * @param separator the separator marking hierarchy
     * @return whether the value is within the prefix
     */
    public static boolean isWithin(String value, Optional<String> prefix, String separator) {
        if (prefix.isEmpty() || prefix.get().isBlank()) {
            return true;
        }

        String scope = prefix.get();
        // Segment-aware on purpose: a plain startsWith would let "platform-archive" through on a
        // prefix of "platform", which is a different entity.
        return value.equals(scope) || value.startsWith(scope + separator);
    }

    private static JsonArray safeArray(UserInfo userInfo, String claim) {
        try {
            return userInfo.getArray(claim);
        } catch (RuntimeException notAnArray) {
            return null;
        }
    }
}
