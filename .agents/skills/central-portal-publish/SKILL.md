---
name: central-portal-publish
description: Publish a component to Maven Central. Use when uploading a deployment bundle, tracking deployment status, publishing or dropping a deployment, or testing a validated bundle as a dependency.
---

# Central Portal Publisher API

Publish a component to Maven Central through the [Central Portal](https://central.sonatype.com) Publisher API. The steps below run in order: prepare the bundle, authenticate, upload, track status to a terminal state, then publish or drop. The full request/response schema lives in the [interactive OpenAPI](https://central.sonatype.com/api-doc); this skill caches only the shapes an agent must construct.

To test a **validated** bundle as a dependency instead of publishing it, follow the disclosure to [manual testing](manual-testing.md).

## 1. Prepare the bundle

A valid deployment bundle is a precondition, built before this skill runs. This skill does not cover bundle assembly (see the [bundle upload guide](https://central.sonatype.org/publish/publish-portal-upload/)).

**Done when** `central-bundle.zip` exists and matches Central's bundle format.

## 2. Authenticate

Build a `Bearer` token once and reuse it on every call.

1. Open the [Account page](https://central.sonatype.com/account), click "Generate User Token" → yields a username and password.
2. `printf "USERNAME:PASSWORD" | base64` → base64 value.
3. Send `Authorization: Bearer <base64 value>` on each request.

**Done when** `$TOKEN` holds the base64 value and an authenticated call succeeds.

> `UserToken` is also accepted but deprecated; prefer `Bearer`.

## 3. Upload the bundle

`POST https://central.sonatype.com/api/v1/publisher/upload`

| Field | Value |
|---|---|
| Content-Type | `multipart/form-data` |
| part | `name=bundle`, `application/octet-stream`, filename `.zip` |
| query — `name` | human label (optional) |
| query — `publishingType` | `AUTOMATIC` or `USER_MANAGED` (default `USER_MANAGED`) |

```
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -F bundle=@central-bundle.zip \
  "https://central.sonatype.com/api/v1/publisher/upload?name=acme-lib&publishingType=USER_MANAGED"
```

**Done when** the response is `201` and the body is the deployment ID (`<uuid>`); store it as `$DEPLOYMENT_ID`.

## 4. Track deployment status

`POST https://central.sonatype.com/api/v1/publisher/status?id=$DEPLOYMENT_ID`

Poll until `deploymentState` reaches a **terminal** value — a state with no further outbound transition, where the run stops.

| State | Role | Transitions to |
|---|---|---|
| `PENDING` | waiting for validation | `VALIDATING` |
| `VALIDATING` | under validation | `VALIDATED` or `FAILED` |
| `VALIDATED` | passed; awaiting your action | `PUBLISHING` (publish) |
| `PUBLISHING` | propagating to Central | `PUBLISHED` |
| `PUBLISHED` | terminal — live on Central | — |
| `FAILED` | terminal — `errors` set | — |

Poll every 5–10s. `AUTOMATIC` bundles flow `VALIDATED → PUBLISHING → PUBLISHED` with no manual step; `USER_MANAGED` pause at `VALIDATED` and wait on step 5.

**Done when** `deploymentState` is `PUBLISHED` (success) or `FAILED` (read `errors`).

## 5. Publish or drop (USER_MANAGED only)

Only a `USER_MANAGED` bundle that reached `VALIDATED` reaches this step.

**Publish** — `POST …/api/v1/publisher/deployment/$DEPLOYMENT_ID` → `204 No Content`, then re-poll status until it leaves `VALIDATED`.

```
curl -X POST -H "Authorization: Bearer $TOKEN" \
  "https://central.sonatype.com/api/v1/publisher/deployment/$DEPLOYMENT_ID"
```

**Drop** — `DELETE …/api/v1/publisher/deployment/$DEPLOYMENT_ID`, valid only at `VALIDATED` or `FAILED`, clears it from history. Do **not** drop a `FAILED` deployment if its files may be needed for a support request.

```
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  "https://central.sonatype.com/api/v1/publisher/deployment/$DEPLOYMENT_ID"
```

**Done when** the call returns `204` and a follow-up status poll no longer reads `VALIDATED`.
