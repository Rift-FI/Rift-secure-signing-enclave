# prod-automation — self-host the Rift signer enclave

Everything an institution (bank, fintech) needs to stand up Rift's signing infrastructure in their own AWS account. Only the enclave + parent-proxy + nginx run on the integrator's EC2 — the smart-wallet and backend are Rift-centralized and resolve per-project routing from Rift's DB on every request.

```
integrator-controls (your AWS)         rift-controls (managed)
├── EC2 (Nitro Enclave)                ├── enclave source (pinned tag)
├── KMS CMK (PCR0-gated)               ├── canonical PCR0 publication
├── parent-proxy (127.0.0.1:7777)      ├── backend (multi-tenant)
├── nginx sidecar (bearer-auth)        ├── smart-wallet (multi-tenant)
├── ALB + ACM + DNS                    └── ProjectEnclaveConfig (per-project
├── Pimlico / RPC API keys                 routing: your URL + bearer +
└── your Rift project ID                    KMS ARN + PCR0 + chains)
```

## Files

| File | What it does |
|---|---|
| [`INTEGRATOR-SETUP.md`](INTEGRATOR-SETUP.md) | The runbook. Start here. |
| [`aws-provision.sh`](aws-provision.sh) | Laptop-side: IAM + KMS + SG + EC2. Idempotent. |
| [`ec2-bootstrap.sh`](ec2-bootstrap.sh) | On the EC2: installs nitro-cli/docker/rust/nginx, clones enclave at a pinned tag, builds EIF, captures PCR0, generates a nginx bearer. |
| [`verify-pcr0.sh`](verify-pcr0.sh) | Compares your built PCR0 against Rift's canonical published value. Run before pinning to KMS. |
| [`templates/`](templates/) | IAM trust + permissions policies; KMS placeholder + hardened policies. |

## What changed vs. the old model

The previous version had integrators run the Node smart-wallet on their EC2 too. That's now dropped — Rift's smart-wallet is centralized and multi-tenant. Integrators:

1. Deploy enclave + parent-proxy + nginx (this folder).
2. Submit their routing config to Rift's admin API once.
3. Rift's smart-wallet automatically routes any user whose `projectId` matches your project into your enclave.

Integrators never touch smart-wallet code, RPCs, JWT secrets, or bundler client logic. They just operate the box that holds the keys.

## Support

- Public: `admin@riftfi.com`
- Security disclosures: `security@riftfi.com`
- Enclave release notes + canonical PCR0s: `https://riftfi.com/enclave/`
