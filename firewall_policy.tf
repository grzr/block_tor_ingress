locals {
  /*
  gcloud organizations list
  */
  organization_id = 100001
}

resource "google_compute_firewall_policy" "block_tor_traffic" {
  parent      = "organizations/${local.organization_id}"
  short_name  = "block-tor-traffic"
  description = "Block traffic to and from TOR exit and relay IPs"
}
