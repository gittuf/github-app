# gittuf/github-app

[gittuf](https://github.com/gittuf/gittuf) relies on signed attestations to
represent code review approvals. The gittuf GitHub app is a helpful bridge
between gittuf policies and GitHub's code review workflow for a pull request.

A public good version of this app is hosted for public github.com repositories.
This is hosted via the Open Source Security Foundation (OpenSSF) where gittuf is
a sandbox project.

## What does this do?

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

## Installation and Getting Started

To install the gittuf app on your repository, see the [installation
documentation](/docs/installation.md).

Once the app is installed on your repository, take a look at the [getting
started documentation](/docs/getting-started.md) for remaining configuration
steps and how to start using the app on your repository.

## Have Questions?

Feel free to reach out on the [OpenSSF Slack](https://slack.openssf.org/) if you
have questions on how the app works, installation, or just want to say hi!
