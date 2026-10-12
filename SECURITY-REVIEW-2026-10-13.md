# Security review — 2026-10-13

Prepared by i729. This review records tested source changes; it is not a certification of the deployed service.

## Change

Store credential/result files privately at creation, use atomic replacement instead of following a credential-file symlink, stop logging generated account tokens/keys, and ignore local lookup results and credentials.

## Validation

Private-file/symlink regression passed; Python source compiled successfully without running API operations.

## Required before rollout

The upstream shared protocol constants are not personal account credentials. No phone lookup, account generation or live GetContact request was performed. Keep credential/CSV/result exports private; deletion from source does not remove an earlier published export. Windows-specific file permission behavior has not been tested.

## Scope

Source and locally fetched Git branches/tags/available pull-request heads were inspected. Private production settings, actual database policies, deployed binaries, backup stores, and third-party service permissions were not changed. Current-source cleanup does not remove data from Git history, existing forks, cached copies, or previously downloaded assets. Sensitive values are intentionally omitted.
