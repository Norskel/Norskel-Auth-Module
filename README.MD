# Quarkus Auth Module

Extension Quarkus fournissant une authentification duale **OIDC** + **API Key JWT** avec gestion utilisateur intégrée.

---

## Table des matières

- [Vue d'ensemble](#vue-densemble)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
- [Utilisation](#utilisation)
- [SPI et extensibilité](#spi-et-extensibilité)
- [API REST exposée](#api-rest-exposée)
- [FAQ et dépannage](#faq-et-dépannage)

---

## Vue d'ensemble

`norskel-auth` est une extension Quarkus qui ajoute à n'importe quelle application :

- Une authentification **OIDC** (testée avec GitLab, compatible Keycloak/Auth0)
- Une authentification par **API Key** sous forme de JWT auto-signé
- Un modèle utilisateur unifié (auto-création au premier login OIDC)
- Des endpoints REST pour gérer les utilisateurs et leurs clés API
- Un SPI pour brancher sa propre persistance (jOOQ, Panache, MongoDB, etc.)
- Une intégration Dev UI pour visualiser/administrer en mode développement

### Cas d'usage cible

L'extension est pensée pour les applications qui doivent accepter **deux types de clients** sur les mêmes endpoints :

- **Utilisateurs humains** authentifiés via un IDP externe (OIDC)
- **Clients machine** (CI, scripts, intégrations) utilisant des clés API longue-durée

Les deux types produisent un `SecurityIdentity` unifié, transparent pour le code métier.

---

## Architecture

### Vue d'ensemble

```
┌──────────────────────────────────────────────────────────────┐
│  HTTP Request                                                 │
│                                                                │
│  Authorization: Bearer <token-opaque-OIDC>                     │
│  OU                                                            │
│  X-Api-Key: <jwt-signé>                                        │
└────────────────────────┬──────────────────────────────────────┘
                         ▼
              ┌──────────────────────┐
              │ HttpAuthentication-  │
              │ Mechanism (Quarkus)  │
              └──────┬───────────────┘
                     │
        ┌────────────┴──────────────┐
        ▼                            ▼
┌──────────────────┐         ┌──────────────────┐
│ OIDC Mechanism   │         │ smallrye-jwt     │
│ (introspection)  │         │ (sig + claims)   │
└────────┬─────────┘         └────────┬─────────┘
         │                            │
         └──────────────┬─────────────┘
                        ▼
            ┌────────────────────────┐
            │  UserRoleAugmentor     │
            │  - upsert OIDC user    │
            │  - check API key       │
            │    revocation          │
            │  - add roles           │
            └───────────┬────────────┘
                        ▼
            ┌────────────────────────┐
            │   SecurityIdentity     │
            │   - principal          │
            │   - roles              │
            │   - user_id            │
            │   - auth_source        │
            └────────────────────────┘
```

### Modules

L'extension suit la structure standard Quarkus :

```
norskel-auth/
├── runtime/        ← code utilisé par l'application finale
└── deployment/     ← BuildSteps, Dev UI, config build-time
```

### Composants principaux

| Composant | Module | Rôle |
|-----------|--------|------|
| `UserService` / `ApiKeyService` | runtime | API métier de haut niveau |
| `UserStore` / `ApiKeyStore` | runtime | SPI de persistance (interfaces) |
| `InMemoryUserStore` / `InMemoryApiKeyStore` | runtime | Implémentations par défaut |
| `UserRoleAugmentor` | runtime | Enrichissement de `SecurityIdentity` |
| `OIDCSecurityIdentitySupplier` | runtime | Logique d'augmentation OIDC |
| `JwtSecurityIdentitySupplier` | runtime | Logique d'augmentation API key |
| `UserResource` / `ApiKeyResource` | runtime | Endpoints REST exposés |
| `AuthBuildTimeConfig` / `AuthRuntimeConfig` | runtime | Configuration |
| `AuthModuleProcessor` | deployment | BuildSteps de l'extension |

---

## Installation

### Dépendance Maven

```xml
<dependency>
    <groupId>net.norskel</groupId>
    <artifactId>auth-module</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

L'extension dépend transitivement de :

- `quarkus-security`
- `quarkus-oidc`
- `quarkus-smallrye-jwt`
- `quarkus-smallrye-jwt-build`
- `quarkus-smallrye-openapi`

Pas besoin de les déclarer explicitement dans le projet consommateur.

### Génération de la paire de clés (API Keys)

L'extension signe les API keys avec une clé RSA. Générez la paire :

```bash
openssl genrsa -out api-token-private.pem 2048
openssl rsa -in api-token-private.pem -pubout -out api-token-public.pem
```

Placez ces fichiers dans `src/main/resources/` de votre application, ou configurez un chemin externe.

> **Sécurité :** la clé privée doit être protégée. En production, montez-la via un secret Kubernetes, Vault, ou variable d'environnement plutôt qu'embarquée dans le jar.

---

## Configuration

### Configuration minimale

```properties
# === OIDC (GitLab dans cet exemple) ===
quarkus.oidc.auth-server-url=https://gitlab.com
quarkus.oidc.client-id=${GITLAB_CLIENT_ID}
quarkus.oidc.credentials.secret=${GITLAB_CLIENT_SECRET}
quarkus.oidc.application-type=service
quarkus.oidc.token.verify-access-token-with-user-info=true
quarkus.oidc.authentication.user-info-required=true

# === API Keys (signature + vérification) ===
mp.jwt.verify.publickey.location=classpath:api-token-public.pem
smallrye.jwt.sign.key.location=api-token-private.pem
```

À partir des propriétés build-time `norskel-auth-build.*`, l'extension préconfigure automatiquement :

- `mp.jwt.token.header=X-Api-Key` (les API keys sont lues sur ce header)
- `mp.jwt.verify.issuer=norskel-auth` (issuer attendu pour les API keys)

Ces valeurs peuvent être overridées dans `application.properties` si besoin.

### Propriétés disponibles

#### Build-time (figées au packaging)

| Property | Défaut | Description |
|----------|--------|-------------|
| `norskel-auth-build.api-token-header` | `X-Api-Key` | Header HTTP portant la clé API |
| `norskel-auth-build.api-token-issuer` | `norskel-auth` | Issuer des JWT API keys |

#### Runtime (modifiables par environnement)

| Property | Défaut | Description |
|----------|--------|-------------|
| `norskel-auth.api-token.default-ttl` | _(vide)_ | TTL de repli (ISO-8601, ex: `P30D`) utilisé quand une clé est créée sans `lifetimeDays`. Si ni l'un ni l'autre n'est fourni, la création est rejetée. |
| `norskel-auth.api-token.track-usage` | `true` | Mise à jour du `lastUsedAt` de la clé à chaque requête authentifiée |
| `norskel-auth.api-token.usage-update-throttle` | `PT1M` | Fréquence minimale d'update du `lastUsedAt` |
| `norskel-auth.user.auto-create-on-oidc` | `true` | Création auto au premier login OIDC |
| `norskel-auth.user.default-role` | `user` | Rôle par défaut des nouveaux utilisateurs |
| `norskel-auth.user.subject-claim` | `sub` | Claim JWT pour l'identifiant utilisateur |
| `norskel-auth.user.email-claims` | `email,preferred_username` | Claims essayés pour l'email (ordre = priorité) |
| `norskel-auth.user.roles-claim` | _(vide)_ | Claim JWT pour récupérer les rôles |

### Exemple complet — production

```properties
# OIDC
quarkus.oidc.auth-server-url=${OIDC_URL}
quarkus.oidc.client-id=${OIDC_CLIENT_ID}
quarkus.oidc.credentials.secret=${OIDC_CLIENT_SECRET}
quarkus.oidc.application-type=service
quarkus.oidc.token.verify-access-token-with-user-info=true
quarkus.oidc.authentication.user-info-required=true
quarkus.oidc.token-cache.max-size=2000
quarkus.oidc.token-cache.time-to-live=5M

# API Keys
mp.jwt.verify.publickey.location=${JWT_PUBLIC_KEY_PATH}
smallrye.jwt.sign.key.location=${JWT_PRIVATE_KEY_PATH}

# Auth Module
norskel-auth.api-token.default-ttl=P90D
norskel-auth.api-token.usage-update-throttle=PT5M
norskel-auth.user.auto-create-on-oidc=true
norskel-auth.user.default-role=hermes_user
norskel-auth.user.email-claims=email,preferred_username
```

---

## Utilisation

### Sécuriser un endpoint

L'extension utilise le système de sécurité standard Quarkus. Toute annotation `@Authenticated`, `@RolesAllowed`, etc. fonctionne immédiatement.

```java
@Path("/api/projects")
public class ProjectResource {

    @GET
    @Authenticated
    public List<Project> list() {
        // Accessible avec OIDC OU API Key
    }

    @POST
    @RolesAllowed("admin")
    public Project create(Project p) {
        // Seuls les admins
    }
}
```

### Récupérer l'utilisateur courant

L'augmentor attache l'`UserEntity` complet en attribut de `SecurityIdentity`. Vous pouvez l'extraire :

```java
@Path("/api/me")
public class MeResource {

    @Inject SecurityIdentity identity;

    @GET
    @Authenticated
    public UserEntity me() {
        return identity.getAttribute("user");
    }
}
```

Ou via le service :

```java
@Inject UserService userService;
@Inject SecurityIdentity identity;

UUID userId = identity.getAttribute("user_id");
UserEntity user = userService.findById(userId);
```

### Distinguer la source d'authentification

L'attribut `auth_source` permet de différencier les flux :

```java
String source = identity.getAttribute("auth_source"); // "oidc" ou "api-key"

if ("api-key".equals(source)) {
    // Logique spécifique aux clients machine
}
```

### Créer une API key

```bash
curl -X POST http://localhost:8080/auth/api-keys/me \
  -H "Authorization: Bearer <oidc-token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-ci-token", "lifetimeDays": 30}'
```

Réponse :
```json
{
  "id": "abc-123",
  "name": "my-ci-token",
  "token": "eyJhbGciOi...",
  "expiresAt": "2026-06-15T10:30:00.000+02:00"
}
```

> **Important :** le token n'est renvoyé qu'**une seule fois** à la création. Stockez-le immédiatement.

### Utiliser une API key

```bash
curl http://localhost:8080/api/projects \
  -H "X-Api-Key: eyJhbGciOi..."
```

---

## SPI et extensibilité

### Fournir sa propre persistance

L'extension utilise des SPI pour la persistance. Par défaut, des stores in-memory sont enregistrés (utiles pour les tests). En production, fournissez vos propres implémentations.

#### Interface `UserStore`

```java
public interface UserStore {
    Optional<UserEntity> findById(UUID id);
    Optional<UserEntity> findByOidcId(String oidcId);
    Optional<UserEntity> findByUsername(String username);
    List<UserEntity> findAll();
    UserEntity persist(UserEntity user);
    UserEntity update(UserEntity user);
}
```

#### Interface `ApiKeyStore`

```java
public interface ApiKeyStore {
    Optional<ApiKeyEntity> findById(UUID id);
    List<ApiKeyEntity> findByUser(UUID userId);
    ApiKeyEntity persist(ApiKeyEntity key);
    ApiKeyEntity update(ApiKeyEntity key);
}
```

#### Exemple — implémentation jOOQ

```java
@ApplicationScoped
public class JooqUserStore implements UserStore {

    @Inject DSLContext dsl;

    @Override
    public Optional<UserEntity> findById(UUID id) {
        return Optional.ofNullable(
            dsl.selectFrom(USERS)
               .where(USERS.ID.eq(id))
               .fetchOne(this::map)
        );
    }

    @Override
    public Optional<UserEntity> findByOidcId(String oidcId) {
        return Optional.ofNullable(
            dsl.selectFrom(USERS)
               .where(USERS.OIDC_ID.eq(oidcId))
               .fetchOne(this::map)
        );
    }

    // ... autres méthodes

    private UserEntity map(Record r) {
        return UserEntity.builder()
            .id(r.get(USERS.ID))
            .username(r.get(USERS.USERNAME))
            .email(r.get(USERS.EMAIL))
            .role(r.get(USERS.ROLE))
            .oidcId(r.get(USERS.OIDC_ID))
            .state(UserStateEnum.valueOf(r.get(USERS.STATE)))
            .createdAt(r.get(USERS.CREATED_AT))
            .lastLogin(r.get(USERS.LAST_LOGIN))
            .build();
    }
}
```

Aucune annotation spéciale nécessaire : votre `@ApplicationScoped` remplacera automatiquement le `@DefaultBean` in-memory.

### Override d'un service

Les services métier (`UserService`, `ApiKeyService`) peuvent également être remplacés. Implémentez l'interface, marquez votre classe `@ApplicationScoped`, et CDI gagnera contre le `@DefaultBean` par défaut.

---

## API REST exposée

L'extension expose deux ressources REST sous le préfixe `/auth/`. Toutes les réponses sont JSON.

### `UserResource` — `/auth/users`

| Méthode | Endpoint | Auth | Description |
|---------|----------|------|-------------|
| `GET` | `/auth/users/me` | `@Authenticated` | Récupère l'utilisateur courant |
| `PUT` | `/auth/users/me` | `@Authenticated` | Met à jour son propre profil |
| `GET` | `/auth/users` | `admin` | Liste tous les utilisateurs |
| `GET` | `/auth/users/{id}` | `admin` | Récupère un utilisateur |
| `POST` | `/auth/users` | `admin` | Crée un utilisateur manuellement |
| `PUT` | `/auth/users/{id}` | `admin` | Met à jour un utilisateur |
| `DELETE` | `/auth/users/{id}` | `admin` | Supprime un utilisateur |
| `POST` | `/auth/users/{id}/ban` | `admin` | Bannit un utilisateur |
| `POST` | `/auth/users/{id}/unban` | `admin` | Débannit un utilisateur |

### `ApiKeyResource` — `/auth/api-keys`

| Méthode | Endpoint | Auth | Description |
|---------|----------|------|-------------|
| `GET` | `/auth/api-keys/me` | `@Authenticated` | Liste ses propres clés |
| `POST` | `/auth/api-keys/me` | `@Authenticated` | Crée une nouvelle clé |
| `DELETE` | `/auth/api-keys/me` | `@Authenticated` | Révoque toutes ses clés |
| `DELETE` | `/auth/api-keys/me/{id}` | `@Authenticated` | Révoque une clé spécifique |
| `GET` | `/auth/api-keys/users/{userId}` | `admin` | Liste les clés d'un utilisateur |
| `GET` | `/auth/api-keys/{id}` | `admin` | Récupère une clé |
| `DELETE` | `/auth/api-keys/{id}` | `admin` | Révoque n'importe quelle clé |
| `DELETE` | `/auth/api-keys/users/{userId}` | `admin` | Révoque toutes les clés d'un user |

### Documentation OpenAPI

L'extension inclut `quarkus-smallrye-openapi`. Une fois l'application démarrée :

- Spec OpenAPI : `http://localhost:8080/q/openapi`
- Swagger UI : `http://localhost:8080/q/swagger-ui/`

---

## FAQ et dépannage

### "GitLab me renvoie un token opaque, pas un JWT"

C'est attendu. GitLab émet par défaut des tokens d'accès opaques. L'extension est configurée pour faire de l'**introspection** côté serveur — Quarkus appelle l'endpoint `/userinfo` de GitLab pour valider le token et récupérer les claims.

Assurez-vous d'avoir :

```properties
quarkus.oidc.token.verify-access-token-with-user-info=true
quarkus.oidc.authentication.user-info-required=true
```

### "Mon UserStore custom n'est pas pris en compte"

Vérifiez que :

1. Il est annoté `@ApplicationScoped`
2. Il est dans un package scanné par CDI (présence d'un `beans.xml` ou annotation directe)
3. Vous n'avez pas accidentellement deux implémentations (l'erreur sera `AmbiguousResolutionException`)

### "Comment révoquer toutes les sessions d'un utilisateur ?"

```java
@Inject ApiKeyService apiKeyService;

apiKeyService.revokeAllForUser(userId);
```

À noter : la révocation invalide les API keys (vérification en base à chaque requête). De plus, bannir un utilisateur bloque immédiatement ses clés API — l'état de l'utilisateur est revérifié à chaque requête authentifiée par clé. En revanche, les tokens OIDC actifs ne sont pas révoqués côté extension ; ils doivent l'être côté IDP.

### "Mes utilisateurs ne sont pas créés automatiquement"

Vérifiez que :

1. `norskel-auth.user.auto-create-on-oidc=true` (valeur par défaut)
2. L'IDP renvoie bien un claim `sub` dans le `userinfo`
3. Le `UserService.upsertFromOidc()` n'échoue pas silencieusement (activez `quarkus.log.category."net.norskel.auth".level=DEBUG`)

### "Erreur de validation de config au démarrage"

Si vous avez `SRCFG00050: ... does not map to any root`, c'est qu'une property dans votre `application.properties` ne matche aucun mapping. Vérifiez :

- Le préfixe (`norskel-auth.*`)
- Le nom kebab-case (`default-role` et non `defaultRole` ou `default_role`)
- Que l'extension est bien rebuild après modification (`mvn clean install` dans le projet de l'extension)

### Activer les logs debug

```properties
quarkus.log.category."net.norskel.auth".level=DEBUG
quarkus.log.category."io.quarkus.oidc".level=DEBUG
quarkus.log.category."io.smallrye.jwt".level=DEBUG
```

---

## Licence

À définir.

## Auteurs

Norskel Team.