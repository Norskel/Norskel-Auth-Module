# Exemple d'utilisation — auth-module

Application Quarkus minimale qui consomme l'extension `auth-module`. Elle sert
deux buts :

1. **Exemple** : montrer ce qu'un projet consommateur doit écrire et configurer.
2. **Test de bout en bout** : prouver que l'extension fonctionne réellement
   lorsqu'elle est utilisée comme dépendance — ce que les tests internes de
   l'extension ne peuvent pas démontrer.

> ⚠️ `dev-only-private-key.pem` est une clé RSA de démonstration, committée pour
> que l'exemple tourne sans configuration. **Ne la réutilisez jamais** : en
> production, montez la clé privée depuis un secret (Vault, secret Kubernetes,
> variable d'environnement) et ne l'empaquetez pas dans le jar.

---

## Démarrer

Depuis la **racine du dépôt** (l'exemple dépend de l'extension, qui doit être
construite d'abord) :

```bash
# Option 1 — jar packagé
./mvnw package -DskipTests
java -jar example-app/target/quarkus-app/quarkus-run.jar

# Option 2 — live reload
./mvnw quarkus:dev -pl :auth-module-example-app
```

Utilisez le wrapper (`./mvnw`, Maven 3.9.11) : `quarkus:dev` sur un module d'un
build multi-modules exige Maven >= 3.9.

### OIDC selon le profil

| Profil | `quarkus.oidc.auth-server-url` | Résultat |
|--------|-------------------------------|----------|
| dev / test | **non défini** | Dev Services démarre un vrai Keycloak (Docker requis) |
| prod (`java -jar`) | placeholder injoignable | démarre sans IDP, seules les clés API fonctionnent |

> Quarkus ne démarre Dev Services for Keycloak **que si
> `quarkus.oidc.auth-server-url` n'est pas défini**. Le définir — comme le
> faisait une version précédente de ce fichier — désactive silencieusement Dev
> Services, ce qui ressemble à un Dev Services cassé. C'est pour cela que la
> propriété est préfixée `%prod.` dans
> [`application.properties`](src/main/resources/application.properties).

En mode prod, aucun serveur OIDC n'est nécessaire : la découverte est désactivée
et les endpoints sont des placeholders, donc rien n'est contacté tant qu'aucun
token `Authorization: Bearer` n'arrive.

Au démarrage, `ExampleBootstrap` crée un utilisateur de démo et deux clés, puis
affiche des commandes `curl` prêtes à coller :

```
===================== auth-module example =====================
Seeded user: demo-admin (role: admin)

User API key — acts as demo-admin:
  curl -s localhost:8080/reports/whoami -H 'X-Api-Key: eyJ...'
...
```

Le seeding est piloté par `example.seed.enabled` (défaut `true`). Mettez-le à
`false` pour démarrer sans données de démo. Écrire des credentials dans les logs
est acceptable pour un exemple et jamais dans une vraie application — d'où
l'avertissement émis si cela tourne hors mode dev/test.

---

## Testeur de routes

Ouvrez <http://localhost:8080/> : une page sans dépendance qui exerce **toutes**
les routes de l'extension et de l'exemple.

- Les deux clés de démo sont préremplies au chargement.
- Un sélecteur à quatre positions — clé utilisateur, clé de service, **token
  OIDC**, ou aucune — c'est le moyen le plus rapide de comparer les
  comportements. La page envoie `X-Api-Key` ou `Authorization: Bearer` selon le
  choix.
- « Obtenir un token OIDC » récupère un vrai token depuis le Keycloak de Dev
  Services, pour `alice` (groups `admin`, `user`) ou `bob` (groups `user`).
- « Tout tester » enchaîne les routes non destructives et affiche chaque statut.
- Les corps JSON sont éditables avant envoi.

> **L'OIDC dans la page ne fonctionne qu'en mode dev/test** (`./mvnw quarkus:dev`),
> puisque Dev Services fournit le Keycloak. Depuis le jar packagé, le bouton
> affiche un bandeau explicatif au lieu d'échouer silencieusement.

Les routes en **rouge** sont exclues de « Tout tester » : bannir ou supprimer
l'utilisateur dont on utilise la clé invalide celle-ci immédiatement, et tout
le reste répondrait 401.

> ⚠️ Deux endpoints alimentent la page : `/example/demo-tokens` (clés API) et
> `/example/oidc-token` (password grant OIDC). Tous deux sont **non authentifiés
> et renvoient des credentials** — acceptable dans un exemple, désastreux en
> production. Ils sont fermés dès que `example.seed.enabled=false`. Ne copiez ni
> `DemoTokenResource` ni `OidcTokenResource` dans un vrai projet.

### Profils observés

Mesurés depuis la page, en ne changeant que l'identité sélectionnée :

| Route | Clé utilisateur | Clé de service | OIDC `alice` | OIDC `bob` |
|-------|-----------------|----------------|--------------|------------|
| `GET /reports/whoami` | 200 | 200 | 200 | 200 |
| `GET /reports/mine` | 200 | **403** (machines exclues) | 200 | 200 |
| `GET /reports/all` | 200 | **403** | 200 | **403** |
| `POST /reports/ingest` | **403** | 200 | **403** | **403** |
| `GET /auth/users/me` | 200 | 200 (sa ligne `SERVICE`) | 200 | 200 |
| `PUT /auth/users/me` | 200 | **403** (lecture seule) | 200 | 200 |
| `GET /auth/users` | 200 | **403** | 200 | **403** |

`alice` atteint les routes `admin` grâce au claim `groups` de son token, alors
que son rôle stocké n'est que `user` : les deux sources de rôles s'additionnent.
`bob`, sans le groupe `admin`, est refusé.

---

## Ce que l'exemple démontre

L'extension produit trois sortes d'identité authentifiée. Un service **est** un
utilisateur de type `SERVICE`, donc toutes portent un `user_id` : ce qui les
distingue est `auth_source`, pas l'absence d'utilisateur.

| Endpoint | Protection | Clé utilisateur | Clé de service |
|----------|-----------|-----------------|----------------|
| `GET /reports/whoami` | `@Authenticated` | 200 | 200 |
| `GET /reports/mine` | `@Authenticated` + personnes only | 200 | **403** |
| `GET /reports/all` | `@RolesAllowed("admin")` | 200 | **403** |
| `POST /reports/ingest` | `@RolesAllowed("report-ingest")` | **403** | 200 |
| `GET /auth/users/me` | fourni par l'extension | 200 | 200 |
| `PUT /auth/users/me` | fourni par l'extension | 200 | **403** |

### Le pattern à copier

`ReportResource.mine()` est l'exemple de référence : pour savoir s'il y a une
**personne** derrière la requête, tester `auth_source` — pas la présence d'un
utilisateur, qui serait non-null pour un service aussi.

```java
// Correct : un service a bien un UserEntity, donc user != null ne prouve rien.
if (AuthAttributes.SOURCE_SERVICE_API_KEY
        .equals(identity.getAttribute(AuthAttributes.AUTH_SOURCE))) {
    throw new ForbiddenException("réservé aux personnes");
}
```

Le seul attribut réellement absent pour une personne est `service_name`.

### Rôles non hiérarchiques

`/reports/ingest` exige `report-ingest`, pas `admin` : le service peut ingérer
des rapports et **rien d'autre**. Un rôle dédié évite de donner `admin` à un
service, ce qui lui permettrait aussi de créer d'autres services.

---

## Tests

```bash
./mvnw verify       # depuis la racine
```

`ExampleAppTest` couvre le chemin clé API, `OidcFlowTest` couvre le chemin OIDC
contre le Keycloak de Dev Services : auto-création au premier login, réutilisation
du même utilisateur aux logins suivants, cumul des rôles, et blocage immédiat
d'un utilisateur banni malgré un token encore valide.

> **Docker est requis** pour la suite de tests de ce module, puisque Dev Services
> démarre un conteneur Keycloak (~460 Mo, ~10 s au premier démarrage).

### Le piège du scope `openid`

L'extension impose `user-info-required=true`. L'endpoint `userinfo` de Keycloak
répond **403 à un token qui ne porte pas le scope `openid`**, ce que l'application
traduit en un simple **401** sans détail. Un client qui demande un token avec un
autre scope (par ex. `microprofile-jwt` seul) échouera donc systématiquement.
Voir `OidcFlowTest#bearer()`.

---

## Configuration à retenir

Voir [`application.properties`](src/main/resources/application.properties) pour
le détail commenté. Les deux pièges :

- `mp.jwt.verify.issuer` doit être épinglé en dev/test, sinon smallrye-jwt le
  fait pointer sur `https://quarkus.io/issuer` et la vérification échoue.
- `quarkus.oidc.authentication.user-info-required=true` est requis par
  l'extension, et **avec la découverte désactivée** il faut aussi déclarer
  `quarkus.oidc.user-info-path`, sinon l'application ne démarre pas.

---

## Pointer vers un vrai IDP

Remplacez le bloc OIDC par :

```properties
quarkus.oidc.auth-server-url=https://votre-idp/realms/votre-realm
quarkus.oidc.client-id=votre-client
quarkus.oidc.credentials.secret=${OIDC_SECRET}
quarkus.oidc.application-type=service
quarkus.oidc.authentication.user-info-required=true
```

Avec la découverte activée (par défaut), les `*-path` deviennent inutiles.
