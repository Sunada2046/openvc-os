# Contributing

Thank you for helping improve OpenVC OS.

## Privacy requirements

Contributions must use synthetic data only. Never commit:

- credentials, tokens, private keys, session cookies, or environment files;
- real companies, investors, employees, emails, phone numbers, or addresses;
- database files, uploads, backups, screenshots, browser traces, or logs;
- organization-specific table identifiers or external record identifiers;
- proprietary prompts, field packs, documents, or connector configuration.

## Development

```bash
npm install
npm run db:init
npm test
```

Before opening a pull request:

1. Run all tests and `npm audit`.
2. Confirm a fresh database contains zero records.
3. Confirm no new outbound connection occurs by default.
4. Add tests for authentication, authorization, data isolation, and input
   validation when changing a security boundary.
5. Explain any new dependency and its license.

## Design principles

- Default deny.
- Local and empty by default.
- Explicit user action before network access.
- Provider-neutral core and separately reviewed adapters.
- Server-side authorization for every protected operation.
- No security control that exists only in the user interface.
