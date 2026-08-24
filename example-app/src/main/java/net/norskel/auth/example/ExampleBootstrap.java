package net.norskel.auth.example;

import io.quarkus.runtime.LaunchMode;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import net.norskel.auth.module.runtime.entities.UserEntity;
import net.norskel.auth.module.runtime.spi.ApiKeyService;
import net.norskel.auth.module.runtime.spi.UserService;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import java.time.Duration;

/**
 * Seeds a demo user plus one key of each kind, and prints ready-to-paste curl
 * commands so the example is usable without an identity provider.
 *
 * <p>Controlled by {@code example.seed.enabled} so the packaged jar is runnable
 * too, not just {@code quarkus:dev}. Printing credentials to the log is
 * acceptable in a sample and never in a real application — hence the warning
 * when this runs outside dev/test.
 */
@ApplicationScoped
public class ExampleBootstrap {

    private static final Logger LOG = Logger.getLogger(ExampleBootstrap.class);

    @Inject
    UserService userService;

    @Inject
    ApiKeyService apiKeyService;

    @ConfigProperty(name = "example.seed.enabled", defaultValue = "true")
    boolean seedEnabled;

    private volatile String userToken;
    private volatile String serviceToken;
    private volatile String adminUserId;

    /** The seeded user API key, or {@code null} when seeding is disabled. */
    public String userToken() {
        return userToken;
    }

    /** The seeded service API key, or {@code null} when seeding is disabled. */
    public String serviceToken() {
        return serviceToken;
    }

    /** Id of the seeded demo admin, or {@code null} when seeding is disabled. */
    public String adminUserId() {
        return adminUserId;
    }

    void onStart(@Observes StartupEvent event) {
        if (!seedEnabled) {
            return;
        }
        if (LaunchMode.current() == LaunchMode.NORMAL) {
            LOG.warn("example.seed.enabled=true in production mode: demo "
                    + "credentials are about to be written to the log. Never do "
                    + "this in a real application.");
        }

        UserEntity admin = userService.create(UserEntity.builder()
                .username("demo-admin")
                .email("admin@example.test")
                .role("admin")
                .oidcId("demo-oidc-admin")
                .build());

        this.adminUserId = admin.getId().toString();

        this.userToken = apiKeyService
                .create(admin.getId(), "demo-user-key", Duration.ofDays(30))
                .token();

        // A dedicated role, not "admin": this service may ingest reports and
        // nothing else. createServiceKey creates a UserEntity of type SERVICE
        // named "report-collector" and issues an ordinary key owned by it.
        this.serviceToken = apiKeyService
                .createServiceKey("report-collector", "nightly-ingest",
                        "report-ingest", Duration.ofDays(90))
                .token();

        LOG.infof("""

                ===================== auth-module example =====================
                Seeded user: demo-admin (role: admin)

                User API key — acts as demo-admin:
                  curl -s localhost:8080/reports/whoami -H 'X-Api-Key: %s'
                  curl -s localhost:8080/reports/mine   -H 'X-Api-Key: %s'
                  curl -s localhost:8080/reports/all    -H 'X-Api-Key: %s'

                Service API key — acts as the 'report-collector' SERVICE user:
                  curl -s localhost:8080/reports/whoami        -H 'X-Api-Key: %s'
                  curl -s -XPOST localhost:8080/reports/ingest -H 'X-Api-Key: %s'
                  curl -s localhost:8080/reports/mine          -H 'X-Api-Key: %s'  # 403: people only
                  curl -s localhost:8080/auth/users/me         -H 'X-Api-Key: %s'  # 200: its own row

                Management endpoints from the extension:
                  curl -s localhost:8080/auth/users             -H 'X-Api-Key: %s'
                  curl -s localhost:8080/auth/api-keys/service  -H 'X-Api-Key: %s'

                Or open the route tester:  http://localhost:8080/
                ===============================================================
                """,
                this.userToken, this.userToken, this.userToken,
                this.serviceToken, this.serviceToken, this.serviceToken, this.serviceToken,
                this.userToken, this.userToken);
    }
}
