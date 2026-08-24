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
- Des **identités de service** (utilisateurs de type `SERVICE`) porteuses de clés API
- Un modèle utilisateur unifié (auto-création au premier login OIDC)
- Des endpoints REST pour gérer les utilisateurs et leurs clés API
- Un SPI pour brancher sa propre persistance (jOOQ, Panache, MongoDB, etc.)

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
├── deployment/     ← BuildSteps, config build-time
└── example-app/    ← application de démo consommant l'extension
```

Un exemple exécutable se trouve dans [`example-app/`](example-app/README.md).
Depuis la racine : `mvn package -DskipTests` puis
`java -jar example-app/target/quarkus-app/quarkus-run.jar` démarre une
application qui affiche des commandes `curl` prêtes à l'emploi.

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

> ⚠️ `user-info-required=true` est obligatoire : `OIDCSecurityIdentitySupplier`
> lit l'attribut `userinfo` et rejette l'authentification s'il est absent. Trois
> conséquences :
>
> - Si vous désactivez la découverte (`quarkus.oidc.discovery-enabled=false`), il
>   faut **aussi** déclarer `quarkus.oidc.user-info-path`, sinon l'application
>   échoue au démarrage avec `UserInfo is required but
>   'quarkus.oidc.user-info-path' is not configured.`
> - Les tokens doivent porter le scope **`openid`**. Sans lui, l'endpoint
>   `userinfo` de Keycloak répond 403 et l'application renvoie un 401 sans
>   explication.
> - Définir `quarkus.oidc.auth-server-url` **désactive Dev Services for
>   Keycloak**. En dev/test, laissez la propriété absente pour obtenir un
>   Keycloak automatique ; voir [`example-app/`](example-app/README.md).

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
    boolean deleteById(UUID id);   // true si un user a été supprimé
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

> Toute clé a un `userId`, y compris celles d'un service : il n'y a **qu'une**
> forme de clé, donc aucun discriminant à respecter côté implémentation.

### Gestion des erreurs

Les erreurs métier des services sont traduites en statuts HTTP par
`AuthExceptionMappers`, avec un corps `{"error": "...", "message": "..."}` :

| Exception | Statut | Cas typique |
|-----------|--------|-------------|
| `AuthNotFoundException` | `404` | User ou clé API inexistant |
| `AuthValidationException` | `400` | TTL absent ou non positif |
| `AuthConflictException` | `409` | Username/oidcId déjà pris, clé pour un user banni |
| `AuthForbiddenException` | `403` | Révocation d'une clé dont on n'est pas propriétaire |

Ces exceptions étendent respectivement `NoSuchElementException`,
`IllegalArgumentException`, `IllegalStateException` et `SecurityException`. Une
implémentation de store qui lève les types JDK reste donc compatible — mais
seuls les sous-types de l'extension sont mappés, afin de ne pas modifier la
façon dont l'application hôte rapporte ses propres erreurs.

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
| `DELETE` | `/auth/api-keys/{id}` | `admin` | Révoque n'importe quelle clé (user ou système) |
| `DELETE` | `/auth/api-keys/users/{userId}` | `admin` | Révoque toutes les clés d'un user |
| `GET` | `/auth/api-keys/service` | `admin` | Liste les clés de service |
| `POST` | `/auth/api-keys/service` | `admin` | Crée une clé de service |

---

## Clés de service (identités de service)

Un **service est un utilisateur** de type `SERVICE` : une ligne `UserEntity` sans
`oidcId` ni `email`, qui possède des clés API comme n'importe quel utilisateur.

C'est un choix délibéré. Il n'existe ni seconde entité, ni store supplémentaire,
ni forme de clé particulière — donc rien à discriminer. Le cycle de vie
utilisateur est réutilisé tel quel : bannir la ligne désactive toutes ses clés
d'un coup, le rôle appartient à l'identité au lieu d'être recopié sur chaque clé,
et l'unicité du nom est celle des `username`.

```bash
curl -X POST http://localhost:8080/auth/api-keys/service \
  -H "X-Api-Key: <clé-admin>" -H "Content-Type: application/json" \
  -d '{"serviceName":"billing-worker","name":"nightly-batch",
       "role":"billing","lifetimeDays":90}'
```

L'appel crée (ou réutilise) l'utilisateur `SERVICE` nommé `billing-worker`, puis
émet une clé ordinaire lui appartenant. La réponse contient le token en clair
**une seule fois**, comme pour une clé utilisateur.

### Forme de l'identité

Une identité de service porte bien un `user_id` — celui de sa ligne `SERVICE`.
Le code applicatif distingue donc les machines des personnes via `auth_source`
(constantes dans `AuthAttributes`), **jamais** via l'absence d'utilisateur :

| Attribut | Clé utilisateur | Clé de service |
|----------|-----------------|----------------|
| `auth_source` | `api-key` | `service-api-key` |
| `user_id` | l'UUID du user | l'UUID de la ligne `SERVICE` |
| `user` | le `UserEntity` | le `UserEntity` du service |
| `service_name` | absent | ex. `billing-worker` |
| rôles | ceux du user | ceux de la ligne `SERVICE` |

### Cycle de vie

- **Kill switch** : `POST /auth/users/{id}/ban` sur la ligne du service
  désactive immédiatement **toutes** ses clés. C'est la façon recommandée de
  couper un service compromis.
- **Rotation** : rappeler `POST /auth/api-keys/service` avec le même
  `serviceName` émet une clé supplémentaire. Plusieurs clés actives par service
  sont donc permises — c'est ce qui rend la rotation sans coupure possible.
- **Changement de rôle refusé** en passant par la création de clé : un
  `serviceName` existant avec un rôle différent renvoie 409. Modifiez
  l'utilisateur explicitement (`PUT /auth/users/{id}`).
- **Lecture seule sur soi-même** : une clé de service peut lire
  `GET /auth/users/me` et `GET /auth/api-keys/me`, mais toute écriture sur les
  endpoints `/me` renvoie 403 — sinon une clé fuitée pourrait s'émettre une
  remplaçante qui survivrait à la révocation de la clé fuitée.
- **Révocation d'une clé précise** : `DELETE /auth/api-keys/{id}` (rôle `admin`).
- L'expiration et le suivi de `lastUsedAt` fonctionnent comme pour les clés
  utilisateur.

> ⚠️ Un `SERVICE` avec `role: "admin"` peut créer d'autres services, puisque
> l'endpoint est protégé par `@RolesAllowed("admin")`. Attribuez un rôle dédié
> (`billing`, `report-ingest`, …) et n'accordez `admin` que si le service doit
> réellement administrer l'authentification.

### Traçabilité (`created_by`)

`UserEntity` et `ApiKeyEntity` portent un `created_by` : l'identité qui a créé la
ligne ou émis la clé. C'est de la **provenance**, pas de la propriété — pour une
clé de service, `user_id` est le service et `created_by` l'admin qui l'a montée.

- Le champ est `READ_ONLY` en JSON : un client ne peut pas le falsifier, la valeur
  est toujours celle de l'appelant authentifié.
- `null` pour une personne auto-créée via OIDC, et pour les clés émises par
  programme (bootstrap, tests).

> ⚠️ **Départ d'un administrateur** : bannir son compte désactive ses propres
> clés, mais **pas** les services qu'il a créés — ceux-ci appartiennent à leur
> propre ligne `SERVICE`. Auditez `GET /auth/api-keys/service` et
> `GET /auth/users`, filtrez sur `created_by`, et bannissez les lignes `SERVICE`
> devenues orphelines.

### Créer un service directement

`POST /auth/api-keys/service` est un raccourci. L'endpoint utilisateur standard
fonctionne aussi, ce qui permet de créer un service sans lui émettre de clé :

```bash
curl -X POST http://localhost:8080/auth/users \
  -H "X-Api-Key: <clé-admin>" -H "Content-Type: application/json" \
  -d '{"username":"billing-worker","role":"billing","type":"SERVICE"}'
```

Règles par type, vérifiées à la création :

| Champ | `HUMAN` | `SERVICE` |
|-------|---------|-----------|
| `username` | requis | requis (et unique) |
| `email` | requis | doit être absent |
| `oidc_id` | requis | doit être absent |
| `role` | optionnel (défaut configuré) | requis |

Un login OIDC dont le `preferred_username` correspond à un service existant est
**refusé** (409) : les usernames viennent de l'IDP, qu'on ne contrôle pas, et une
personne ne doit pas pouvoir usurper le nom d'un service dans les logs et audits.

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