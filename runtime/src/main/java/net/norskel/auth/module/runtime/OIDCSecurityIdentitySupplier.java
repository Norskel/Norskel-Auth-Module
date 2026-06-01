package net.norskel.auth.module.runtime;

import io.quarkus.oidc.UserInfo;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import jakarta.enterprise.context.Dependent;
import jakarta.inject.Inject;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import net.norskel.auth.module.runtime.config.AuthRuntimeConfig;
import net.norskel.auth.module.runtime.entities.UserEntity;
import net.norskel.auth.module.runtime.enums.UserStateEnum;
import net.norskel.auth.module.runtime.spi.UserService;

import java.util.function.Supplier;

/**
 * OIDCSecurityIdentitySupplier
 *
 * @author Norskel
 * @since 30.03.2026
 **/
@Dependent
@Slf4j
public class OIDCSecurityIdentitySupplier implements Supplier<SecurityIdentity> {

    @Setter
    private SecurityIdentity identity;


    @Inject
    UserService userService;

    @Inject
    AuthRuntimeConfig config;

    @Override
    public SecurityIdentity get() {
        // 1. Récupérer les infos utilisateur depuis l'introspection OIDC
        UserInfo userInfo = identity.getAttribute("userinfo");
        if (userInfo == null) {
            log.warn("[OIDC] No userinfo attribute on identity — userinfo required?");
            throw new AuthenticationFailedException("Missing userinfo from OIDC provider");
        }

        String subject = userInfo.getString("sub");
        if (subject == null || subject.isBlank()) {
            log.warn("[OIDC] Missing 'sub' claim in userinfo");
            throw new AuthenticationFailedException("Missing subject claim");
        }

        String email = userInfo.getString("email");
        String name = firstNonBlank(
                userInfo.getString("preferred_username"),
                userInfo.getString("nickname"),
                userInfo.getString("name"),
                email);

        log.debug("[OIDC] Resolving user sub={} email={}", subject, email);

        // 2. Upsert en base
        UserEntity user;
        try {
            user = userService.upsertFromOidc(subject, email, name);
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

        return QuarkusSecurityIdentity.builder(identity)
                .addRole(role)
                .addAttribute("user_id", user.getId())
                .addAttribute("user", user)
                .addAttribute("auth_source", "oidc")
                .build();
    }

    private static String firstNonBlank(String... values) {
        for (String v : values) {
            if (v != null && !v.isBlank()) return v;
        }
        return null;
    }
}
