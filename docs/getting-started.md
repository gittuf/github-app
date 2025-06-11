# Getting Started with the gittuf GitHub App

NOTE: This document only applies to the hosted version of the app for github.com
repositories.

## Step 0: Decide functionality level

First, you'll need to decide on the level of functionality that you'd like to 
utilize from the app. There are two modes:

- **Lite mode**. If you'd like to simply have the app observe approvals on pull
  requests, then you can setup the app in lite mode. The app records
  attestations for pull request approvals and merges, and can be used to
  generate source provenance attestations for the upcoming SLSA source track.
  The lite mode is recommended if you're interested in slowly ramping up with
  gittuf use.
- **Full mode**. If, instead, you'd like to use the information captured by the
  app to enforce a security policy, you'll need to set up the app in full
  mode. In this mode, the repository is configured with a specific policy. For
  example, you can configure the maintainers of the repository as approvers for
  changes, and validate the attestations recorded by the app against the policy
  to ensure the right approvals were issued.

The setup for both modes is identical until the app is installed on the 
repository. The guide will highlight where the installation process diverges.

## Step 1: Install the app

To install the app on your repository, visit the GitHub [app
listing](https://github.com/apps/gittuf-app-beta). Select the account to install
the app under (e.g. under your personal account or an organization), and for
which repositories.

If you plan to use the app in lite mode, then the setup is complete! If you are
setting up the app in full mode, proceed to step 2 below.

## Step 2: Setup full mode

Initialize gittuf metadata on the repository following the [get started
guide](https://github.com/gittuf/gittuf/blob/main/docs/get-started.md) for
gittuf. At the end of this initialization, the repository must have the minimum
set of gittuf metadata including the root of trust.

To this root of trust, add the public key of the gittuf GitHub app and enable
it:

```bash
# Download the public key to verify app attestation signatures
curl -o /tmp/gittuf-app-key.pub https://raw.githubusercontent.com/gittuf/github-app/refs/heads/main/docs/hosted-app-key.pub
chmod 600 /tmp/gittuf-app-key.pub

# Specify the signing key that you previously configured as trusted for the root
# metadata
gittuf trust add-github-app -k <your signing key> --app-key /tmp/gittuf-app-key.pub
gittuf trust enable-github-app-approvals -k <your signing key>

# Stage and apply the policy
gittuf policy stage <remote name>
gittuf policy apply <remote name>
```

NOTE: The app uses a fixed signing key. When the app's signing key is updated,
the gittuf metadata will also have to be updated with the new key.
