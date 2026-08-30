# Firmware Release Publisher

## Overview

This project implements a firmware release publisher that reconciles firmware build data, creates canonical release descriptors, signs them using the current code-signing key, and publishes the signed descriptors through the distribution gateway.

The original issue was caused by a signing-key rotation. The legacy publisher continued using a revoked signing certificate, causing the distribution gateway to reject release bundles with:

`UNTRUSTED_SIGNATURE`

The implementation updates the publishing workflow to use the current signing credentials.

---

## Main Implementation

The main development work is in:

```text
publisher/release-publisher.mjs


01a02a89-47d1-78e7-8599-b3ba03ccf530