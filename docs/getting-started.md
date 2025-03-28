# The gittuf GitHub App

gittuf enables **independently verifiable** security policies to be defined for
a repository. These policies rely on signed commits in Git and signed [in-toto
attestations](https://github.com/in-toto/attestation).

An example of this is defining rules that require a threshold of users to
approve a change. On GitHub, this is done by opening a pull request and users
approving the changes. With gittuf, approving changes must be done by running
the gittuf tool to update the gittuf metadata in the repository as needed. The
GitHub app for gittuf bridges this usability gap and allows using GitHub pull
request reviews to satisfy gittuf policy requirements.

The attestations recorded by the app for pull request approvals can also be used
to meet the upcoming **[SLSA source
track](https://slsa.dev/spec/draft/source-requirements)**. However, as the
source track is still under development, the attestations may evolve when SLSA
requirements change.

## How does the app work?

Once installed, the gittuf GitHub app monitors your repository for pull request
and push events via [GitHub
webhooks](https://docs.github.com/en/webhooks/about-webhooks). Whenever a user
approves a pull request, the app records this information in the repository as a
[code review approval
attestation](https://github.com/gittuf/gittuf/blob/main/docs/gaps/6/README.md).
This attestation can be used to verify that the change meets gittuf policy. The
app also adds a status check to pull requests that indicate whether the
available approvals meet the configured gittuf policy.

NOTE: the app needs **push access** to the repository as the code review
attestations are stored as blobs in the repository.

## Installation

The app is available in beta and can be installed from the GitHub app
marketplace: https://github.com/apps/gittuf-app-beta.

Today, there are two modes of operation to use the app. In the "lite" mode, the
app is installed without configuring gittuf policy for the repository. The app
records attestations for pull request approvals and merges, and can be used to
generate source provenance attestations for the [upcoming SLSA source
track](https://slsa.dev/spec/draft/source-requirements). The lite mode is
recommended if you're interested in slowly ramping up with gittuf use.

In the "full" mode, the repository is configured with a specific policy. For
example, you can configure the maintainers of the repository as approvers for
changes, and validate the attestations recorded by the app against the policy to
ensure the right approvals were issued.

### Installing the app on your repository (Full, Lite)

To install the app on your repository, visit the GitHub [marketplace
listing](https://github.com/apps/gittuf-app-beta). The UI will walk you through
the standard installation process. As a part of this, it will prompt you to
select which account to install the app under (e.g. under your personal account
or an organization).

### Configuring gittuf to trust the GitHub app (Full-only)

First, initialize gittuf metadata on the repository following the [get started
guide](https://github.com/gittuf/gittuf/blob/main/docs/get-started.md) for
gittuf.

Next, authorize the GitHub app to record information in your repository by
running the following commands:

```bash
# Download the public key to verify app attestation signatures
curl -o /tmp/gittuf-app-key.pub https://raw.githubusercontent.com/gittuf/github-app/refs/heads/main/docs/hosted-app-key.pub
chmod 600 /tmp/gittuf-app-key.pub

# Specify the signing key that you previously configured as trusted for the root
# metadata
gittuf trust add-github-app -k <your signing key> --app-key /tmp/gittuf-app-key.pub

# Stage and apply the policy
gittuf policy stage --local-only
gittuf policy apply --local-only

# Push the gittuf policy
git push <remote name> refs/gittuf/*
```

NOTE: the app uses a fixed signing key. When the app's signing key is updated,
the gittuf metadata will also have to be updated with the new key.
