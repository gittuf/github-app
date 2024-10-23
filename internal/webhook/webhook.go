// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/gittuf/gittuf/experimental/gittuf"
	githubopts "github.com/gittuf/gittuf/experimental/gittuf/options/github"
	rslopts "github.com/gittuf/gittuf/experimental/gittuf/options/rsl"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/go-github/v61/github"
)

/*
	This is heavily inspired by the webhook in
	https://github.com/chainguard-dev/octo-sts written by @wlynch.
*/

const (
	reviewStateApproved = "approved"
	reviewTypeSubmitted = "submitted"
	reviewTypeDismissed = "dismissed"

	gitZeroHash = "0000000000000000000000000000000000000000"

	DefaultGitHubURL     = "https://github.com"
	SSHAppSigningKeyPath = "/root/.ssh/key"
)

type EnvConfig struct {
	// Port indicates what port the app is served on.
	Port int `envconfig:"PORT" required:"true" default:"8080"`

	// DevMode is enabled only for initial PoC/testing of the app.  This flow
	// will be removed and must not be used for production deployments.
	DevMode bool `envconfig:"DEV_MODE" default:"false"`

	// KMSKey records the KMS identifier for the signing key to use for
	// interactions with the GitHub instance. When DevMode is true, this is
	// parsed as a path to a private key file on disk.
	KMSKey string `envconfig:"KMS_KEY" required:"true"`

	// GitHubURL indicates the URL of the GitHub instance the app is deployed
	// for.
	GitHubURL string `envconfig:"GITHUB_URL" default:"https://github.com"`

	// AppID indicates the app's ID provided by the GitHub instance the app is
	// deployed on.
	AppID int64 `envconfig:"GITHUB_APP_ID" required:"true"`

	// WebhookSecret contains the secret configured with the GitHub instance for
	// communications from the server.
	WebhookSecret string `envconfig:"GITHUB_WEBHOOK_SECRET" required:"true"`

	// AppEmailID is the email ID used for commits created by the app.
	AppEmailID string `envconfig:"APP_EMAIL_ID" required:"true"`

	// CloudProvider identifies the cloud provider used for the KMS and secrets
	// manager.
	CloudProvider string `envconfig:"CLOUD_PROVIDER" default:"gcp"`

	// AppSigningKey indicates the secret used as the signing private key for
	// the app's signatures.
	AppSigningKey string `envconfig:"APP_SIGNING_KEY" required:"true"`

	// AppSigningPubKey indicates the secret used as the public key for the
	// app's signatures.
	AppSigningPubKey string `envconfig:"APP_SIGNING_PUBKEY" required:"true"`
}

type GittufApp struct {
	Transport     *ghinstallation.AppsTransport
	WebhookSecret [][]byte
	Params        *EnvConfig

	init sync.Once
}

func (g *GittufApp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.init.Do(func() {
		// TODO: maybe do this in docker file?

		cmd := exec.Command("git", "config", "--global", "user.name", "gittuf-github-app")
		if err := cmd.Run(); err != nil {
			panic(err)
		}

		cmd = exec.Command("git", "config", "--global", "user.email", g.Params.AppEmailID) //nolint:gosec
		if err := cmd.Run(); err != nil {
			panic(err)
		}

		// main.go sets up this key for us
		cmd = exec.Command("git", "config", "--global", "user.signingkey", SSHAppSigningKeyPath)
		if err := cmd.Run(); err != nil {
			panic(err)
		}

		cmd = exec.Command("git", "config", "--global", "gpg.format", "ssh")
		if err := cmd.Run(); err != nil {
			panic(err)
		}
	})

	log.Default().Printf("Serving app...")

	payload, err := g.validatePayload(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Default().Printf("Validated payload, received: %s", string(payload))

	eventType := github.WebHookType(r)
	event, err := github.ParseWebHook(eventType, payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Default().Printf("Event type: %s", reflect.TypeOf(event).String())

	switch event := event.(type) {
	case *github.PushEvent:
		if err := g.handlePush(r.Context(), event); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	case *github.PullRequestEvent:
		if err := g.handlePullRequest(r.Context(), event); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	case *github.PullRequestReviewEvent:
		if err := g.handlePullRequestReview(r.Context(), event); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
}

func (g *GittufApp) validatePayload(r *http.Request) ([]byte, error) {
	// Taken from github.ValidatePayload - we can't use this directly since the body is consumed.
	signature := r.Header.Get(github.SHA256SignatureHeader)
	if signature == "" {
		signature = r.Header.Get(github.SHA1SignatureHeader)
	}
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	for _, s := range g.WebhookSecret {
		payload, err := github.ValidatePayloadFromBody(contentType, bytes.NewBuffer(body), signature, s)
		if err == nil {
			return payload, nil
		}
	}
	return nil, errors.New("no matching secrets")
}

func (g *GittufApp) handlePush(ctx context.Context, event *github.PushEvent) error {
	owner := event.GetRepo().GetOwner().GetLogin()
	repository := event.GetRepo().GetName()
	installationID := event.GetInstallation().GetID()

	log.Default().Printf("Push action on %s/%s for reference %s, installation of app %d", owner, repository, event.GetRef(), installationID)

	if event.GetAfter() == gitZeroHash {
		// this is a deletion, do nothing
		log.Default().Printf("Push action is to delete ref %s", event.GetRef())
		return nil
	}

	transport := ghinstallation.NewFromAppsTransport(g.Transport, installationID)
	token, err := transport.Token(ctx)
	if err != nil {
		return err
	}

	cloneURL := event.GetRepo().GetCloneURL()

	parsedURL, err := url.Parse(cloneURL)
	if err != nil {
		return err
	}
	parsedURL.User = url.UserPassword("x-access-token", token)
	cloneURL = parsedURL.String()

	localDirectory, err := os.MkdirTemp("", "gittuf")
	if err != nil {
		return err
	}

	if _, err := git.PlainClone(localDirectory, false, &git.CloneOptions{URL: cloneURL}); err != nil {
		log.Default().Print("clone: " + err.Error())
		return err
	}

	// TODO: might interfere with other instances?
	os.Setenv("GIT_DIR", filepath.Join(localDirectory, ".git"))
	defer os.Unsetenv("GIT_DIR")

	os.Setenv("GITTUF_DEV", "1") // TODO

	repo, err := gittuf.LoadRepository()
	if err != nil {
		return err
	}
	gitRepo := repo.GetGitRepository()

	if err := gitRepo.Fetch("origin", []string{"refs/gittuf/*"}, true); err != nil {
		log.Default().Print("fetch gittuf and base: " + err.Error())
		return err
	}

	switch {
	case strings.HasPrefix(event.GetRef(), "refs/heads"):
		log.Default().Print("Pushed ref is a branch...")
		refSpec := fmt.Sprintf("%s:refs/gittuf/local-ref", event.GetRef())
		if err := gitRepo.FetchRefSpec("origin", []string{refSpec}); err != nil {
			log.Default().Print("fetch branch: " + err.Error())
			return err
		}

		if err := repo.RecordRSLEntryForReference("refs/gittuf/local-ref", true, rslopts.WithOverrideRefName(event.GetRef())); err != nil {
			log.Default().Print("rsl record: " + err.Error())
			return err
		}
	case strings.HasPrefix(event.GetRef(), "refs/tags"):
		refSpec := fmt.Sprintf("%s:%s", event.GetRef(), event.GetRef())
		if err := gitRepo.FetchRefSpec("origin", []string{refSpec}); err != nil {
			log.Default().Print("fetch tag: " + err.Error())
			return err
		}

		if err := repo.RecordRSLEntryForReference(event.GetRef(), true); err != nil {
			log.Default().Print("rsl record: " + err.Error())
			return err
		}
	}

	if err := gitRepo.Push("origin", []string{"refs/gittuf/reference-state-log"}); err != nil {
		log.Default().Print("push gittuf: " + err.Error())
		return err
	}

	return nil
}

// handlePullRequest creates an RSL entry when a pull request is merged for the
// base branch.
func (g *GittufApp) handlePullRequest(ctx context.Context, event *github.PullRequestEvent) error {
	owner := event.GetRepo().GetOwner().GetLogin()
	repository := event.GetRepo().GetName()
	installationID := event.GetInstallation().GetID()

	log.Default().Printf("Action on %s/%s#%d, installation of app %d", owner, repository, event.GetPullRequest().GetNumber(), installationID)

	if !event.PullRequest.GetMerged() {
		// Nothing to do
		return nil
	}

	transport := ghinstallation.NewFromAppsTransport(g.Transport, installationID)

	cloneURL := event.GetPullRequest().GetBase().GetRepo().GetCloneURL()

	parsedURL, err := url.Parse(cloneURL)
	if err != nil {
		return err
	}

	token, err := transport.Token(ctx)
	if err != nil {
		return err
	}
	parsedURL.User = url.UserPassword("x-access-token", token)
	cloneURL = parsedURL.String()

	localDirectory, err := os.MkdirTemp("", "gittuf")
	if err != nil {
		return err
	}

	if _, err := git.PlainClone(localDirectory, false, &git.CloneOptions{URL: cloneURL, ReferenceName: plumbing.ReferenceName(event.GetPullRequest().GetBase().GetRef())}); err != nil {
		log.Default().Print("clone: " + err.Error())
		return err
	}

	// TODO: might interfere with other instances?
	os.Setenv("GIT_DIR", filepath.Join(localDirectory, ".git"))
	defer os.Unsetenv("GIT_DIR")

	repo, err := gittuf.LoadRepository()
	if err != nil {
		return err
	}
	gitRepo := repo.GetGitRepository()

	if err := gitRepo.Fetch("origin", []string{"refs/gittuf/*"}, true); err != nil {
		log.Default().Print("fetch gittuf and base: " + err.Error())
		return err
	}

	signer, err := gittuf.LoadSigner(repo, SSHAppSigningKeyPath)
	if err != nil {
		return err
	}

	os.Setenv("GITTUF_DEV", "1") // TODO

	// Get token again in case it's expired
	token, err = transport.Token(ctx)
	if err != nil {
		return err
	}

	if err := repo.AddGitHubPullRequestAttestationForCommit(ctx, signer, owner, repository, event.GetPullRequest().GetMergeCommitSHA(), event.GetPullRequest().GetBase().GetRef(), true, githubopts.WithGitHubBaseURL(g.Params.GitHubURL), githubopts.WithGitHubToken(token)); err != nil {
		return err
	}

	if err := repo.RecordRSLEntryForReference(event.GetPullRequest().GetBase().GetRef(), true); err != nil {
		log.Default().Print("rsl entry creation: " + err.Error())
		return err
	}

	if err := gitRepo.Push("origin", []string{"refs/gittuf/*"}); err != nil {
		log.Default().Print("push gittuf: " + err.Error())
		return err
	}

	return nil
}

// handlePullRequestReview observes pull request review events. If a pull
// request is approved, it records an attestation with the details of the
// approver as well as the nature of the change (updated base branch, base
// commit, target tree ID). If an approval is dismissed, it updates the
// corresponding attestation to indicate the approver has changed their mind.
func (g *GittufApp) handlePullRequestReview(ctx context.Context, event *github.PullRequestReviewEvent) error {
	owner := event.GetRepo().GetOwner().GetLogin()
	repository := event.GetRepo().GetName()
	installationID := event.GetInstallation().GetID()

	log.Default().Printf("Review on %s/%s#%d, installation of app %d", owner, repository, event.GetPullRequest().GetNumber(), installationID)

	transport := ghinstallation.NewFromAppsTransport(g.Transport, installationID)

	client := github.NewClient(&http.Client{
		Transport: transport,
	})

	var err error
	if g.Params.GitHubURL != DefaultGitHubURL {
		log.Default().Print("Enterprise instance found, creating enterprise client")
		log.Default().Printf("Instance url: %s", g.Params.GitHubURL)
		base := fmt.Sprintf("%s/%s/%s/", g.Params.GitHubURL, "api", "v3")
		upload := fmt.Sprintf("%s/%s/%s", g.Params.GitHubURL, "api", "uploads")
		client, err = client.WithEnterpriseURLs(base, upload)
		if err != nil {
			return err
		}
	}

	// Who was the approver?
	reviewer := event.Review.GetUser()
	reviewerIdentifier := fmt.Sprintf("%s+%d", reviewer.GetLogin(), reviewer.GetID())

	cloneURL := event.GetPullRequest().GetBase().GetRepo().GetCloneURL()

	parsedURL, err := url.Parse(cloneURL)
	if err != nil {
		return err
	}

	token, err := transport.Token(ctx)
	if err != nil {
		return err
	}
	parsedURL.User = url.UserPassword("x-access-token", token)
	cloneURL = parsedURL.String()

	localDirectory, err := os.MkdirTemp("", "gittuf")
	if err != nil {
		return err
	}

	if _, err := git.PlainClone(localDirectory, false, &git.CloneOptions{URL: cloneURL, ReferenceName: plumbing.ReferenceName(event.GetPullRequest().GetBase().GetRef())}); err != nil {
		log.Default().Print("clone: " + err.Error())
		return err
	}

	// TODO: might interfere with other instances?
	os.Setenv("GIT_DIR", filepath.Join(localDirectory, ".git"))
	defer os.Unsetenv("GIT_DIR")

	repo, err := gittuf.LoadRepository()
	if err != nil {
		return err
	}
	gitRepo := repo.GetGitRepository()

	if err := gitRepo.Fetch("origin", []string{"refs/gittuf/*"}, true); err != nil {
		log.Default().Print("fetch gittuf and base: " + err.Error())
		return err
	}

	// Fetch feature ref
	// We fetch using github's refs/pull/<number>/head ref as the feature ref
	// may be from a different repository
	refSpec := fmt.Sprintf("refs/pull/%d/head:refs/heads/%s", event.GetPullRequest().GetNumber(), event.GetPullRequest().GetHead().GetRef())
	if err := gitRepo.FetchRefSpec("origin", []string{refSpec}); err != nil {
		log.Default().Print("fetch feature branch: " + err.Error())
		return err
	}

	signer, err := gittuf.LoadSigner(repo, SSHAppSigningKeyPath)
	if err != nil {
		return err
	}

	// Get token again in case it's expired
	token, err = transport.Token(ctx)
	if err != nil {
		return err
	}

	os.Setenv("GITTUF_DEV", "1") // TODO
	var message string
	switch event.GetAction() {
	case reviewTypeSubmitted:
		if event.GetReview().GetState() != reviewStateApproved {
			log.Default().Printf("review submitted by '%s' on PR %s/%s#%d is not for approval", reviewer.GetLogin(), owner, repository, event.GetPullRequest().GetNumber())
			return nil
		}

		if err := repo.AddGitHubPullRequestApprover(ctx, signer, owner, repository, event.GetPullRequest().GetNumber(), event.GetReview().GetID(), reviewerIdentifier, true, githubopts.WithGitHubBaseURL(g.Params.GitHubURL), githubopts.WithGitHubToken(token)); err != nil {
			log.Default().Print("gittuf attest: " + err.Error())
			return err
		}

		message = fmt.Sprintf("Observed review from %s (@%s)", reviewerIdentifier, reviewer.GetLogin())

	case reviewTypeDismissed:
		if err := repo.DismissGitHubPullRequestApprover(ctx, signer, event.GetReview().GetID(), reviewerIdentifier, true, githubopts.WithGitHubBaseURL(g.Params.GitHubURL), githubopts.WithGitHubToken(token)); err != nil {
			log.Default().Print("gittuf attest: " + err.Error())
			return err
		}

		message = fmt.Sprintf("Observed dismissal of review by %s (@%s)", reviewerIdentifier, reviewer.GetLogin())
	}

	if err := gitRepo.Push("origin", []string{"refs/gittuf/*"}); err != nil {
		log.Default().Print("push gittuf: " + err.Error())
		return err
	}

	log.Default().Printf("Created message: %s", message)

	commentCreated, response, err := client.Issues.CreateComment(ctx, owner, repository, event.GetPullRequest().GetNumber(), &github.IssueComment{
		Body: &message,
	})
	if err != nil {
		return fmt.Errorf("unable to create GitHub comment: %w", err)
	}

	log.Printf("Comment created: %s", commentCreated.GetBody())
	log.Printf("Response: %s", response.Status)
	log.Default().Println("Commented!")

	return nil
}
