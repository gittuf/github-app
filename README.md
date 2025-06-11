# gittuf/github-app

[gittuf](https://gittuf.dev) enables **independently verifiable** security
policies to be defined for a repository. These policies rely on signed commits
in Git and signed [in-toto
attestations](https://github.com/in-toto/attestation).

## What does this do?

The gittuf GitHub app is a helpful bridge between gittuf policies and GitHub's
code review workflow for a pull request. For example, you may want a minimum
number of code review approvals for a pull request to be merged. The GitHub app
for gittuf allows using GitHub pull request reviews to satisfy gittuf policy
requirements.

A public good version of this app is hosted for public github.com repositories.
This is hosted via the Open Source Security Foundation (OpenSSF) where gittuf is
an incubating project. Alternatively, you can deploy this app yourself for
repositories hosted on github.com or on an on-premises GitHub enterprise
instance.

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

To install the gittuf app on your repository, see the [getting
started documentation](/docs/getting-started.md). It'll walk you through 
deciding how you'd like to deploy the app on your repository, and any 
additional steps that you'll need to take after installation.

## Have Questions?

Feel free to reach out on the [OpenSSF Slack](https://slack.openssf.org/) if you
have questions on how the app works, installation, or just want to say hi!
