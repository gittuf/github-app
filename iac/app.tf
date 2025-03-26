data "google_service_account" "github-app-sa" {
  account_id = "gittuf-app@gittuf-451517.iam.gserviceaccount.com"
}

resource "google_service_account_iam_member" "service_account_user" {
  service_account_id = data.google_service_account.github-app-sa.id
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${module.github-ci-gsa.email}"
}

resource "google_kms_key_ring_iam_member" "key_ring" {
  key_ring_id        = "global/gittuf-github-app"
  role               = "roles/cloudkms.signer"
  member             = "serviceAccount:${module.github-ci-gsa.email}"
}
