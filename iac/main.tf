terraform {
  backend "gcs" {
    bucket = "gittuf-tfstate"
  }
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "6.23.0"
    }
  }
}

provider "google" {
  project = var.project
}
