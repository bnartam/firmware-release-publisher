# Firmware Release Publisher

## Task

Implement the firmware release publisher in:

`publisher/release-publisher.mjs`

The publisher must reconcile the firmware build manifest, create canonical release descriptors, sign them using the current firmware code-signing key, publish them through the distribution gateway, and persist publication receipts for idempotent reruns.

## Requirements

### 1. Manifest reconciliation

Load:

`fixtures/build_manifest.csv`

into DuckDB.

The publisher must:

- Ignore exact duplicate manifest rows.
- Consider only `BUILD` records for publication.
- Apply `WITHDRAWAL` records using `supersedes_id`.
- Exclude builds that have been withdrawn.
- Group surviving builds by `bundle_id`.
- Calculate:
  - `artifact_count`
  - `total_bytes`
- Process bundles in ascending `bundle_id` order.

### 2. Canonical descriptor

For every publishable bundle, create a canonical JSON descriptor containing:

- `artifact_count`
- `bundle_id`
- `total_bytes`

The JSON object keys must be lexicographically sorted and contain no insignificant whitespace.

The exact descriptor bytes must be used for signing and must be sent unchanged to the gateway.

### 3. Current signing key

Retrieve the current signing-key metadata from:

`GET /v1/signing-key/current`

Use the current signing credentials to create a detached CMS signature using OpenSSL.

The publisher must not use the revoked signing key.

### 4. Publication

Submit each signed descriptor to:

`POST /v1/publications`

using:

```json
{
  "descriptor": "<canonical descriptor>",
  "signature": "<PEM detached CMS signature>",
  "request_token": "token-<bundle_id>"
}