# The gittuf GitHub App

[gittuf](https://github.com/gittuf/gittuf) is a security layer for Git
repositories. For repositories that use GitHub, the gittuf project maintains a
GitHub app to help users get started with using gittuf, with minimal changes to
existing developer workflows.

## What is this for?

gittuf enables various security policies to be defined for a repository. These
policies rely on signed commits in Git, but also on additional mechanisms
introduced by gittuf (such as attestations).

An example of this is defining rules that require a threshold of users to
approve a change. On GitHub, this is done by opening a pull request and users
approving the changes. With gittuf, approving changes must be done by running
the gittuf tool to update the gittuf metadata in the repository as needed.

Since GitHub pull request data is not stored inside the repository, gittuf is
unable to make use of this data directly. The GitHub app for gittuf bridges this
gap and allows using GitHub pull request reviews to satisfy gittuf policy
requirements.

## What can it do?

Once installed, the gittuf GitHub app monitors your repository for pull
requests. Whenever a user approves a pull request, the app records this
information in the repository as an
[attestation](https://github.com/gittuf/gittuf/blob/main/docs/design-document.md#attestations-for-authorization-records).
The app and gittuf then use these attestations when determining whether a commit
was made in the repository in accordance with policy. In addition to capturing
approvals, the app is also aware of when users _dismiss_ their approval, and
records this data in the repository as well.

To assist with seeing if a change is in compliance with policy, the app shows up
as a check in the pull request. This check has a status message indicating
whether the proposed changes will satisfy the gittuf policy defined for the
repository.

## Installation

Installing the gittuf GitHub app requires configuring the GitHub app itself as
well as configuring gittuf on your repository to authorize the GitHub app to
record approvals to changes.

Please note that this guide assumes that you are familiar with the basics of
gittuf. To learn more about gittuf, visit [gittuf.dev](https://gittuf.dev)

### Installing the app on your repository

[//]: # (TODO: App installation website; marketplace?)

[//]: # (TODO: Abuse note? e.g. we reserve the right to monitor usage to prevent overuse?)

To install the app on your repository, visit the GitHub
[marketplace listing](TODO). The UI will walk you through the standard
installation process. As a part of this, it will prompt you to select which
account to install the app under (e.g. under your personal account or an
organization). The app is free to install and use.

As a part of this setup process, the app will generate a key that it uses to
sign the attestations it adds to the repository. **Make note of this key.** You
will need it to configure gittuf, as described below.

The installation flow will also ask you to select the repositories that you
would like to install the app on. Make sure that you select repositories that
have gittuf already initialized on them, as the app will not work otherwise.

### Configuring gittuf to trust the GitHub app

First, ensure that you have initialized gittuf on the repository. You do not
need to define a policy should you wish to simply capture approvals inside the
repository.

To authorize the GitHub app to record information in your repository, you must
run the following commands:

```bash
# Replace the keys below as appropriate
gittuf trust add-github-app -k <your signing key> --app-key <the key provided by the app>

# Stage and apply the policy
gittuf policy stage
gittuf policy apply
```

From here, the GitHub app will be able to start recording activity on pull
requests in your repository.
