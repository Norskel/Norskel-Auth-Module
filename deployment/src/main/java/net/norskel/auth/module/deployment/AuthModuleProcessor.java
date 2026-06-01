package net.norskel.auth.module.deployment;

import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.deployment.builditem.RunTimeConfigurationDefaultBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;
import net.norskel.auth.module.runtime.DualAuthMechanism;
import net.norskel.auth.module.runtime.JwtSecurityIdentitySupplier;
import net.norskel.auth.module.runtime.OIDCSecurityIdentitySupplier;
import net.norskel.auth.module.runtime.UserRoleAugmentor;
import net.norskel.auth.module.runtime.config.AuthBuildTimeConfig;
import net.norskel.auth.module.runtime.entities.ApiKeyEntity;
import net.norskel.auth.module.runtime.entities.UserEntity;
import net.norskel.auth.module.runtime.resources.ApiKeyResource;
import net.norskel.auth.module.runtime.resources.UserResource;
import net.norskel.auth.module.runtime.services.ApiKeyServiceImpl;
import net.norskel.auth.module.runtime.store.InMemoryApiKeyStore;
import net.norskel.auth.module.runtime.store.InMemoryUserStore;

class AuthModuleProcessor {

    private static final String FEATURE = "auth-module";

    @BuildStep
    FeatureBuildItem feature() {
        return new FeatureBuildItem(FEATURE);
    }

    @BuildStep
    AdditionalBeanBuildItem registerBean() {
        return AdditionalBeanBuildItem.builder()
                .setUnremovable()
                .addBeanClasses(
                        ApiKeyServiceImpl.class,
                        InMemoryApiKeyStore.class,
                        InMemoryUserStore.class,
                        ApiKeyResource.class,
                        UserResource.class,
                        DualAuthMechanism.class,
                        UserRoleAugmentor.class,
                        OIDCSecurityIdentitySupplier.class,
                        JwtSecurityIdentitySupplier.class)
                .build();
    }

    @BuildStep
    void configureDefaults(
            BuildProducer<RunTimeConfigurationDefaultBuildItem> defaults, AuthBuildTimeConfig authBuildTimeConfig) {

        // smallrye-jwt lit les api-keys sur X-Api-Key
        defaults.produce(new RunTimeConfigurationDefaultBuildItem(
                "mp.jwt.token.header", authBuildTimeConfig.apiTokenHeader()));

        // mp.jwt.verify.issuer par défaut
        defaults.produce(new RunTimeConfigurationDefaultBuildItem(
                "mp.jwt.verify.issuer", authBuildTimeConfig.apiTokenjwtIssuer()));

        // L'utilisateur peut override ces valeurs dans son application.properties
    }

    /**
     * Enregistre les classes utilisées par réflexion pour la compilation
     * native. Sans ça, Jackson/JSON-B ne pourraient pas sérialiser UserEntity
     * en mode natif.
     */
    @BuildStep
    ReflectiveClassBuildItem registerReflection() {
        return ReflectiveClassBuildItem.builder(UserEntity.class, ApiKeyEntity.class)
                .methods(true)
                .fields(true)
                .build();
    }


}
