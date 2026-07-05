# prod-automation — self-host the Rift signer enclave

Everything an institution (bank, fintech) needs to stand up Rift's signing infrastructure in their own AWS account. The signer runs inside an AWS Nitro Enclave; your users' keys are generated and used inside the enclave and never accessible to Rift or to you as the operator.

```
integrator-controls-everything
├── AWS account, region, VPC     ← your infra
├── EC2 (Nitro Enclave)          ← runs the signer
├── KMS CMK                      ← attestation-gated
├── ALB + ACM + DNS              ← your endpoint
└── Pimlico / RPC / secrets      ← your commercial accounts

rift-controls-code
├── enclave source (pinned tag)  ← reproducible PCR0
├── canonical PCR0 publication   ← verify what you built = what we ship
└── backend routing              ← calls your smart-wallet URL
```

## Files

| File | What it does |
|---|---|
| [`INTEGRATOR-SETUP.md`](INTEGRATOR-SETUP.md) | The runbook. Start here. |
| [`aws-provision.sh`](aws-provision.sh) | Laptop-side: creates IAM, KMS, security group, EC2. Idempotent. |
| [`ec2-bootstrap.sh`](ec2-bootstrap.sh) | On the EC2: installs nitro-cli/docker/rust, clones enclave at a pinned tag, builds EIF, captures PCR0. |
| [`verify-pcr0.sh`](verify-pcr0.sh) | Compares your built PCR0 against Rift's canonical published value. Run before pinning. |
| [`smart-wallet-bootstrap.sh`](smart-wallet-bootstrap.sh) | On the EC2: clones smart-wallet, writes env, installs systemd unit. |
| [`templates/`](templates/) | IAM trust + permissions policies; KMS placeholder + hardened policies. |

## Read this first

`INTEGRATOR-SETUP.md` is the runbook. It walks you from empty AWS account to sandbox live in 12 steps, with a security-critical manual checkpoint at step 6. Reading it end-to-end takes 15 min; running it takes 2–3 hours the first time.

## Support

- Public: `admin@riftfi.com`
- Security disclosures: `security@riftfi.com`
- Enclave release notes + canonical PCR0s: `https://riftfi.com/enclave/`
