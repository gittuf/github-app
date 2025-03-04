# Federation

This directory contains setup for setting up CI/CD workload identity between
GitHub <-> GCP.

This must be run by an admin with permissions on GCP.

To apply this, run:

```sh
gcloud auth application-default-login
terraform apply
```
