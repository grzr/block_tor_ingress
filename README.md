
# Block Ingress traffic from TOR exit nodes

Aim is to block TOR ingress traffic [1] using GCP organizational FW Policy [2].
Currently it generate 1700 entries in hierarchical FW Policy - it is not far from GCP limits [3].

## Installation

```shell
pip install -r requirements.txt
python3 generate_google_compute_firewall_policy_rules.py

gcloud organizations list
# edit firewall_policy.tf
terraform apply
```

## Sources

* [1] https://lists.fissionrelays.net/tor/
* [2] https://cloud.google.com/armor/docs/security-policy-overview
* [3] https://cloud.google.com/vpc/docs/quota#per_organization
