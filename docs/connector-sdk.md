# Connector SDK Contract

OpenVC OS uses a provider-neutral manifest. The open core stores and reviews the
manifest but does not execute it.

```json
{
  "schemaVersion": 1,
  "capabilities": ["read"],
  "objectTypes": ["deal"],
  "dataClassifications": ["internal"],
  "destinations": [],
  "requiresApproval": true
}
```

## Required adapter properties

An adapter package must:

- declare every capability and destination;
- request the minimum object and field scope;
- reject undeclared redirects and destinations;
- apply timeouts, response-size limits, and request budgets;
- redact secrets and confidential values from logs;
- require explicit administrator activation;
- write an audit event for every attempted external action;
- support immediate disablement and credential rotation;
- never send data before a user-visible approval when approval is required.

## Secret handling

Secret values are submitted separately from manifests. The core encrypts them
with AES-256-GCM and never returns plaintext through the API. Production adapter
deployments should prefer an operating-system key store or managed secret
service and use the local vault only as a compatibility fallback.

## MCP adapters

An MCP adapter is treated like any other external connector. It must use an
explicit server address, tool allowlist, data-classification ceiling, execution
budget, and approval policy provided by the operator. No server or tool is
trusted merely because it implements the protocol.
