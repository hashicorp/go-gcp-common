# Vault-Google Cloud Platform Common Library

Utilities for Vault and GCP integrations. Includes helpers for:
- Parsing GCP credential JSON or finding default credentials
- Various helpers for some GCP APIs

This library was created to be shared by Vault-GCP integrations including the:
- [GCP Auth Method](https://github.com/hashicorp/vault-plugin-auth-gcp)
- [GCP Secrets Engine](https://github.com/hashicorp/vault-plugin-secrets-gcp)

## Usage:

```go

import "github.com/hashicorp/go-vault-gcp-common/gcputil"
```
