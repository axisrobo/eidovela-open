# EIDOVELA v1 Enrollment Attestation Profile

`POST /v1/enrollments/complete` completes a `private_key_jwt` enrollment. For
workloads registered on a platform that requires a verified attestor
(`spiffe_svid`, `k8s_projected_sa`, `mtls`), the request may carry optional
attestation evidence:

| Field | Type | Description |
|---|---|---|
| `attestation.method` | string | `spiffe_svid` \| `k8s_projected_sa` \| `mtls` |
| `attestation.certificate_pem` | string | PEM leaf certificate for `spiffe_svid` / `mtls` |
| `attestation.token` | string | Raw projected service-account JWT for `k8s_projected_sa` |

When present, the server invokes the matching workload attestor and derives
trusted selector attributes from the evidence instead of trusting the
caller-supplied `workload_attributes`. The attestor enforces the workload
selector and fails closed on:

- an attestation method the workload registration does not permit;
- a SPIFFE SVID whose trust domain does not match the registration `trust_domain`;
- a SPIFFE SVID / mTLS certificate that is malformed, out of validity, or does
  not satisfy the registered selector;
- a Kubernetes projected token whose `iss` does not match the registered
  `kubernetes_issuer` selector, or whose subject/claims do not satisfy the
  selector.

The caller (TLS termination / issuer JWKS layer) is responsible for verifying
the certificate chain or token signature before submission; the enrollment
service performs semantic and selector verification only.
