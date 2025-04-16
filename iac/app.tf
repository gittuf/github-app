data "google_service_account" "github-app-sa" {
  account_id = "gittuf-app@gittuf-451517.iam.gserviceaccount.com"
}

resource "google_service_account_iam_member" "service_account_user" {
  service_account_id = data.google_service_account.github-app-sa.id
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${module.github-ci-gsa.email}"
}

resource "google_cloud_run_service_iam_binding" "default" {
  location = "us-central1"
  service  = "app"
  role     = "roles/run.invoker"
  members = [
    "allUsers"
  ]
}

resource "google_kms_key_ring_iam_member" "key_ring" {
  key_ring_id        = "global/gittuf-github-app"
  role               = "roles/cloudkms.signer"
  member             = "serviceAccount:${data.google_service_account.github-app-sa.email}"
}

resource "google_secret_manager_secret_iam_binding" "github_webhook_secret" {
  secret_id = "github-webhook-secret"
  role = "roles/secretmanager.secretAccessor"
  members = [
    "serviceAccount:${data.google_service_account.github-app-sa.email}"
  ]
}

resource "google_secret_manager_secret_iam_binding" "gittuf_app_signing_key" {
  secret_id = "gittuf-app-signing-key"
  role = "roles/secretmanager.secretAccessor"
  members = [
    "serviceAccount:${data.google_service_account.github-app-sa.email}"
  ]
}

resource "google_secret_manager_secret_iam_binding" "gittuf_app_signing_pubkey" {
  secret_id = "gittuf-app-signing-pubkey"
  role = "roles/secretmanager.secretAccessor"
  members = [
    "serviceAccount:${data.google_service_account.github-app-sa.email}"
  ]
}
