# Architecture

## Goals

OpenVC OS provides a useful VC operating-system core without embedding an
institution's records, terminology, field mappings, identity provider, model
provider, or integration endpoints.

## Components

```text
Browser
  |
  | HttpOnly session cookie + CSRF token
  v
Local API on loopback
  |-- authentication and role authorization
  |-- organization-scoped query boundary
  |-- object and relation service
  |-- field-definition service
  |-- disabled connector registry
  |-- document storage boundary
  `-- audit service
       |
       v
SQLite + owner-only local files
```

## Data model

The core separates four concerns:

1. `objects` stores organization-owned business records by type.
2. `relations` links records without hard-coding every cross-module relation.
3. `field_definitions` describes user-owned fields, types, classifications, and
   formulas.
4. `connectors` stores disabled, provider-neutral manifests; credentials are
   encrypted separately.

Typed object values live in `data_json`, while stable identity, organization,
status, timestamps, and deletion state remain relational columns. This is a
deliberate trade-off: it enables user-defined structures without schema
migrations for every custom field. High-volume deployments may later promote
frequently queried fields into indexed materialized columns.

## Authentication

- No account exists before local setup.
- Passwords use Argon2id.
- Session and CSRF tokens are random and stored only as hashes.
- Cookies are HttpOnly and SameSite Strict.
- Failed logins are rate limited.
- Roles are created only when the operator creates the workspace.
- Authorization is enforced by the API, not by navigation visibility.

## Multi-tenancy

Every business table includes `organization_id`. Queries derive the organization
from the authenticated session and never accept it from request payloads. The
initial local deployment normally contains one organization, but the boundary
is explicit for future hosted or multi-organization deployment.

## Connectors

The connector registry is an inventory, not an execution engine. The core:

- ships with zero connector records;
- contains no provider endpoint or credential name;
- creates connectors in a disabled state;
- rejects credentials embedded in manifests;
- encrypts separately submitted secret values;
- never executes an outbound connector.

Adapter execution requires a separate package and an explicit deployment
decision. This keeps the public core auditable and prevents silent data egress.
