---
name: central-portal-publishing
description: "Namespace publishing to Maven Central: sign up, claim and verify a namespace (DNS TXT or code-hosting repo), join an organization, publish components."
---

# Central Portal namespace publishing

Covers the workflow for getting a verified **namespace** and publishing components to Maven Central via the Central Portal. Publishing requires a verified namespace; a published component is immutable — fix errors by publishing a new version.

## Steps

### Sign up for an account
At <https://central.sonatype.com>, click Sign In. The Portal supports Google, GitHub, or a username and password you choose. Provide an email you can access — Central uses it to complete signup and to reach you for support.

From the authenticated session, open your username menu → "View Namespaces".

Done when you have an authenticated session and the Namespaces view is open.

### Claim a namespace
A namespace is your Maven `groupId` — the first coordinate of `groupId:artifactId:version`. Choose one form:

- **Owned domain** — reverse it: `example.com` → `com.example`; deeper subdomains attach left (`sub.example.com` → `com.example`).
- **Code-hosting service** — `io.github.<username>`, `io.gitlab.<username>`, `io.gitee.<username>`, `io.bitbucket.<username>`, `io.sourceforge.<username>`.

Sign in with GitHub and Central auto-verifies `io.github.<your-username>` — skip to publishing.

On the Namespaces view, click "Add Namespace", enter the namespace, click "Submit". The request appears in "Unverified" state with a "Verify Namespace" button.

Done when the namespace is listed as "Unverified" with a View ID / Verify action available.

### Verify the namespace
The namespace card menu → "View ID" copies the Verification Key Central assigned. Prove ownership one way, and Confirm only after the proof is live:

- **DNS** — add a TXT record to the exact domain. The `com.example` namespace is checked at `example.com`, not `com.example.com` or any subdomain. The record value is the Verification Key.
- **Code hosting** — create a public repository named with the Verification Key (e.g. `github.com/<username>/<verification-key>`).

Then click "Verify Namespace" → "Confirm" to move to "Verification Pending". The state flips to "Verified" within minutes; refresh to confirm. An unverified DNS record caches NXDOMAIN and delays verification past the usual window.

Done when the namespace state reads "Verified".

### Publish components
With a verified namespace, publish using a supported client — the [Central Publisher Maven plugin](https://central.sonatype.org/publish/publish-portal-maven/), the [Publisher API](https://central.sonatype.org/publish/publish-portal-api/), a [bundle upload](https://central.sonatype.org/publish/publish-portal-upload/), or the [Gradle plugin](https://central.sonatype.org/publish/publish-portal-gradle/).

Each upload enters validation (a few minutes) against the [requirements](https://central.sonatype.org/publish/requirements/). On success, click "Publish" to sync to Maven Central. A failed validation lists specifics under "Validation Results" — fix them locally and resubmit.

Done when a deployment shows status "Published" on the Deployments page.

## Reference

### Namespace card actions
- **View ID** — copy the Verification Key
- **Cancel Verification** — return to "Unverified"
- **View History** — inspect verification attempts and errors
- **Remove Namespace** — delete the request entirely

### Organizations
A verified namespace auto-maps to an existing Organization or creates a new one with you as Admin. New Admins serve a 30-day probation (cannot remove, suspend, or promote members) and appear tagged "Under Probation". Roles:

- **Admin** — invite/remove members, manage namespace permissions, view audit logs
- **Member** — publish to granted namespaces only

Admins cannot remove other Admins or be removed while the last Admin remains; every admin action requires a 5–500 character reason. To join an existing organization, an Admin invites you by email (invites expire in 7 days).

### Publishers and credentials
Credential resets live at the bottom of the sign-in form; Central never asks for passwords by email. Usernames are immutable — create a new account for a different username. To change your email or full name, contact [Central Support](mailto:central-support@sonatype.com) (a verification email routes to the new address).

Publishing is tiered: a [free tier](https://central.sonatype.org/publish/producer-terms/) covers open-source use; commercial or service-dependent SDKs incur fees. Publish only genuinely open-source software.
