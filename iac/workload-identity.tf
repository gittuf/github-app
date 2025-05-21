
module "github-wif" {
  source  = "chainguard-dev/common/infra//modules/github-wif-provider"
  version = "0.6.127"

  project_id = var.project
  name       = "github-idpool"
  github_org = "gittuf"

  notification_channels = []
}

module "github-ci-gsa" {
  source  = "chainguard-dev/common/infra//modules/github-gsa"
  version = "0.6.127"

  project_id = var.project
  name       = "github-ci"
  wif-pool   = module.github-wif.pool_name

  repository   = "gittuf/github-app"
  refspec      = "refs/heads/main"
  workflow_ref = ".github/workflows/deploy.yml"

  notification_channels = []
}

resource "google_project_iam_member" "ci-run-developer" {
  project = var.project
  role    = "roles/run.developer"
  member  = "serviceAccount:${module.github-ci-gsa.email}"
}

resource "google_project_iam_member" "ci-artifact-registry-writer" {
  project = var.project
  role    = "roles/artifactregistry.writer"
  member  = "serviceAccount:${module.github-ci-gsa.email}"
}
