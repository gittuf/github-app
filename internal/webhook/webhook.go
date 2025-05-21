// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/gittuf/gittuf/experimental/gittuf"
	githubopts "github.com/gittuf/gittuf/experimental/gittuf/options/github"
	rslopts "github.com/gittuf/gittuf/experimental/gittuf/options/rsl"
	verifymergeableopts "github.com/gittuf/gittuf/experimental/gittuf/options/verifymergeable"
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

	pullRequestActionOpened      = "opened"
	pullRequestActionSynchronize = "synchronize"
	pullRequestActionClosed      = "closed"

	gitZeroHash = "0000000000000000000000000000000000000000"

	DefaultGitHubURL = "https://github.com"
	KeyFileName      = "key"
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

	// CommentOnAffectedPRs indicates whether the app should post a comment
	// on PRs where prior approvals do not hold when the base branch is
	// affected by a push or a merge.
	CommentOnAffectedPRs bool `envconfig:"COMMENT_ON_AFFECTED_PRS" default:"false"`
}

type GittufApp struct {
	Transport     *ghinstallation.AppsTransport
	WebhookSecret [][]byte
	Params        *EnvConfig

	sshSigningKeyPath string
	init              sync.Once
}

func (g *GittufApp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.init.Do(func() {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			panic(err)
		}
		g.sshSigningKeyPath = filepath.Join(homeDir, ".ssh", KeyFileName)

		cmd := exec.Command("git", "config", "--global", "user.name", "gittuf-github-app")
		if err := cmd.Run(); err != nil {
			panic(err)
		}

		cmd = exec.Command("git", "config", "--global", "user.email", g.Params.AppEmailID) //nolint:gosec
		if err := cmd.Run(); err != nil {
			panic(err)
		}

		// main.go sets up this key for us
		cmd = exec.Command("git", "config", "--global", "user.signingkey", g.sshSigningKeyPath) //nolint:gosec
		if err := cmd.Run(); err != nil {
			panic(err)
		}

		cmd = exec.Command("git", "config", "--global", "gpg.format", "ssh")
		if err := cmd.Run(); err != nil {
			panic(err)
		}

		slog.SetDefault(slog.New(slog.NewTextHandler(log.Default().Writer(), &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})))
	})

	log.Default().Printf("Serving app...")

	if err := os.Setenv("GITTUF_DEV", "1"); err != nil {
		panic(err)
	}

	payload, err := g.validatePayload(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	eventType := github.WebHookType(r)
	event, err := github.ParseWebHook(eventType, payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	switch event := event.(type) {
	case *github.PushEvent:
		log.Default().Print("Handling push event...")
		if err := g.handlePush(r.Context(), event); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	case *github.PullRequestEvent:
		log.Default().Print("Handling pull request event...")
		if err := g.handlePullRequest(r.Context(), event); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	case *github.PullRequestReviewEvent:
		log.Default().Print("Handling pull request review event...")
		if err := g.handlePullRequestReview(r.Context(), event); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	default:
		log.Default().Printf("Received event type '%s', not handling event...", eventType)
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
	log.Default().Printf("Repository: %s/%s", owner, repository)

	ref := event.GetRef()
	log.Default().Printf("Ref: %s", ref)

	installationID := event.GetInstallation().GetID()
	log.Default().Printf("Installation ID: %d", installationID)

	currentTip := event.GetAfter()
	if currentTip == gitZeroHash {
		// this is a deletion, do nothing
		log.Default().Print("Push action is to delete ref, nothing else to do")
		return nil
	}

	transport := ghinstallation.NewFromAppsTransport(g.Transport, installationID)
	client, err := getGitHubClient(transport, g.Params.GitHubURL)
	if err != nil {
		return err
	}

	// When a pull request is freshly merged, a push event is triggered.
	// However, sometimes, this API endpoint identifying the PRs for the commit
	// isn't updated quickly enough by the server. We get told that there are no
	// PRs for the commit in question. So, this might incorrectly tell us there
	// are no commits.
	pullRequests, _, err := client.PullRequests.ListPullRequestsWithCommit(ctx, owner, repository, currentTip, nil)
	if err != nil {
		return fmt.Errorf("unable to identify pull requests associated with commit '%s': %w", currentTip, err)
	}
	if len(pullRequests) > 0 {
		// we'll handle this in the PR merge / synchronize event
		log.Default().Printf("Found pull request for commit %s", currentTip)
		return nil
	}

	cloneURL := event.GetRepo().GetCloneURL()

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
	if _, err := git.PlainClone(localDirectory, false, &git.CloneOptions{URL: cloneURL}); err != nil {
		log.Default().Printf("Unable to clone repository: %v", err)
		return err
	}

	repo, err := gittuf.LoadRepository(localDirectory)
	if err != nil {
		return err
	}
	gitRepo := repo.GetGitRepository()

	if err := gitRepo.Fetch("origin", []string{"refs/gittuf/*"}, true); err != nil {
		log.Default().Printf("Unable to fetch gittuf refs: %v", err)
		return err
	}

	switch {
	case strings.HasPrefix(ref, "refs/heads"):
		refSpec := fmt.Sprintf("%s:refs/gittuf/local-ref", ref)
		if err := gitRepo.FetchRefSpec("origin", []string{refSpec}); err != nil {
			log.Default().Printf("Unable to fetch pushed branch: %v", err)
			return err
		}

		if err := repo.RecordRSLEntryForReference(ctx, "refs/gittuf/local-ref", true, rslopts.WithOverrideRefName(ref), rslopts.WithRecordLocalOnly()); err != nil {
			log.Default().Printf("Unable to record RSL entry: %v", err)
			return err
		}
	case strings.HasPrefix(ref, "refs/tags"):
		refSpec := fmt.Sprintf("%s:%s", ref, ref)
		if err := gitRepo.FetchRefSpec("origin", []string{refSpec}); err != nil {
			log.Default().Printf("Unable to fetch tag: %v", err)
			return err
		}

		if err := repo.RecordRSLEntryForReference(ctx, ref, true, rslopts.WithRecordLocalOnly()); err != nil {
			log.Default().Printf("Unable to record RSL entry: %v", err)
			return err
		}
	}

	// When a pull request is freshly merged, a push event is triggered.
	// However, sometimes, this API endpoint identifying the PRs for the commit
	// isn't updated quickly enough by the server. We get told that there are no
	// PRs for the commit in question. We _repeat_ this check at this point to
	// allow the server to catch up. If this time there are PRs returned, we
	// don't have to push the RSL entry we just created.
	log.Default().Printf("Repeating check for pull requests associated with commit '%s'", currentTip)
	pullRequests, _, err = client.PullRequests.ListPullRequestsWithCommit(ctx, owner, repository, currentTip, nil)
	if err != nil {
		return fmt.Errorf("unable to identify pull requests associated with commit '%s': %w", currentTip, err)
	}
	if len(pullRequests) > 0 {
		// there are PRs for the commit after all
		// we'll handle this in the PR merge / synchronize event
		log.Default().Printf("Found pull request for commit %s", currentTip)
		return nil
	}

	if err := gitRepo.Push("origin", []string{"refs/gittuf/reference-state-log"}); err != nil {
		log.Default().Printf("Unable to push RSL: %v", err)
		return err
	}

	return nil
}

// handlePullRequest creates an RSL entry when a pull request is merged for the
// base branch.
func (g *GittufApp) handlePullRequest(ctx context.Context, event *github.PullRequestEvent) error {
	owner := event.GetRepo().GetOwner().GetLogin()
	repository := event.GetRepo().GetName()
	log.Default().Printf("Repository: %s/%s", owner, repository)

	pullRequestNumber := event.GetPullRequest().GetNumber()
	log.Default().Printf("Pull Request: %d", pullRequestNumber)

	installationID := event.GetInstallation().GetID()
	log.Default().Printf("Installation ID: %d", installationID)

	baseRef := event.GetPullRequest().GetBase().GetRef()
	featureRef := event.GetPullRequest().GetHead().GetRef()

	cloneURL := event.GetPullRequest().GetBase().GetRepo().GetCloneURL()
	parsedURL, err := url.Parse(cloneURL)
	if err != nil {
		return err
	}

	transport := ghinstallation.NewFromAppsTransport(g.Transport, installationID)
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
	if _, err := git.PlainClone(localDirectory, false, &git.CloneOptions{URL: cloneURL, ReferenceName: plumbing.ReferenceName(baseRef)}); err != nil {
		log.Default().Printf("Unable to clone repository: %v", err)
		return err
	}

	repo, err := gittuf.LoadRepository(localDirectory)
	if err != nil {
		return err
	}
	gitRepo := repo.GetGitRepository()

	if err := gitRepo.Fetch("origin", []string{"refs/gittuf/*"}, true); err != nil {
		log.Default().Printf("Unable to fetch gittuf refs: %v", err)
		return err
	}

	refSpec := fmt.Sprintf("refs/pull/%d/head:refs/pull/%d/head", pullRequestNumber, pullRequestNumber)
	if err := gitRepo.FetchRefSpec("origin", []string{refSpec}); err != nil {
		log.Default().Printf("Unable to fetch feature branch: %v", err)
		return err
	}

	switch event.GetAction() {
	case pullRequestActionClosed:
		if !event.PullRequest.GetMerged() {
			// Nothing to do
			log.Default().Print("Pull request has not been merged yet, nothing to do")
			return nil
		}

		signer, err := gittuf.LoadSigner(repo, g.sshSigningKeyPath)
		if err != nil {
			return err
		}

		if err := repo.AddGitHubPullRequestAttestationForNumber(ctx, signer, owner, repository, pullRequestNumber, true, githubopts.WithGitHubBaseURL(g.Params.GitHubURL), githubopts.WithGitHubTokenSource(transport), githubopts.WithRSLEntry()); err != nil {
			log.Default().Printf("Unable to create pull request attestation: %v", err)
			return err
		}

		if err := repo.RecordRSLEntryForReference(ctx, baseRef, true, rslopts.WithRecordLocalOnly()); err != nil {
			log.Default().Printf("Unable to create RSL entry: %v", err)
			return err
		}

		if err := gitRepo.Push("origin", []string{"refs/gittuf/*"}); err != nil {
			log.Default().Printf("Unable to push gittuf refs: %v", err)
			return err
		}

		hasPolicy, err := repo.HasPolicy()
		if err != nil {
			log.Default().Printf("Unable to check if policy exists: %v", err)
			return err
		}
		if hasPolicy {
			go func() {
				// Re-run check for all open PRs that have the same base branch
				// This is all in a separate goroutine so we can do this behind
				// the scenes while also abiding by GitHub's webhook response
				// time limit
				client, err := getGitHubClient(transport, g.Params.GitHubURL)
				if err != nil {
					log.Default().Printf("Unable to create GitHub client: %v", err)
					return
				}

				affectedPullRequests, _, err := client.PullRequests.List(ctx, owner, repository, &github.PullRequestListOptions{
					State: "open",
					Base:  baseRef,
				})
				if err != nil {
					log.Default().Printf("Unable to get affected pull requests: %v", err)
					return
				}

				for _, pullRequest := range affectedPullRequests {
					go func() {
						// Run this check in a separate goroutine for each
						// affected PR
						refSpec := fmt.Sprintf("refs/pull/%d/head:refs/pull/%d/head", pullRequest.GetNumber(), pullRequest.GetNumber())
						if err := gitRepo.FetchRefSpec("origin", []string{refSpec}); err != nil {
							log.Default().Printf("Unable to fetch feature branch for affected pull request %d: %v", pullRequest.GetNumber(), err)
							return
						}

						mergeable := false
						if _, err := repo.VerifyMergeable(ctx, baseRef, fmt.Sprintf("refs/pull/%d/head", pullRequest.GetNumber()), verifymergeableopts.WithBypassRSLForFeatureRef()); err == nil {
							// TODO: for now, we're not using the bool return
							mergeable = true
						} else {
							log.Default().Printf("VerifyMergeable failed: %v", err)
						}

						var conclusion, title, summary string
						if mergeable {
							conclusion = "success"
							title = "PR is mergeable!"
							summary = "Sufficient approvals have been submitted for the PR to be mergeable."
						} else {
							conclusion = "neutral"
							title = "PR is not mergeable"
							summary = "More approvals are necessary for the PR to be mergeable."
						}

						sha := pullRequest.GetHead().GetSHA()

						opts := github.CreateCheckRunOptions{
							Name:        "Verify gittuf policy",
							HeadSHA:     sha,
							ExternalID:  github.String(sha),
							Status:      github.String("completed"),
							Conclusion:  github.String(conclusion),
							StartedAt:   &github.Timestamp{Time: time.Now()},
							CompletedAt: &github.Timestamp{Time: time.Now()},
							Output: &github.CheckRunOutput{
								Title:   github.String(title),
								Summary: github.String(summary),
							},
						}

						if _, _, err := client.Checks.CreateCheckRun(ctx, owner, repository, opts); err != nil {
							log.Default().Printf("Unable to recreate check run for PR %d: %s", pullRequest.GetNumber(), err.Error())
							return
						}

						if g.Params.CommentOnAffectedPRs {
							message := fmt.Sprintf("Base branch %s has been updated to %s, older reviews (if any) do not apply anymore.", pullRequest.GetBase().GetRef(), pullRequest.GetBase().GetSHA())
							if _, _, err := client.Issues.CreateComment(ctx, owner, repository, pullRequest.GetNumber(), &github.IssueComment{
								Body: &message,
							}); err != nil {
								return
							}
						}
					}()
				}
			}()
		}

	case pullRequestActionOpened, pullRequestActionSynchronize:
		// Record RSL entry for the branch in question

		if event.GetPullRequest().GetBase().GetRepo().GetID() == event.GetPullRequest().GetHead().GetRepo().GetID() {
			// Record push only if head repo is same as base repo
			absFeatureRef := plumbing.NewBranchReferenceName(featureRef).String()
			log.Default().Printf("Recording RSL entry for 'refs/pull/%d/head', overridden with ref '%s'...", pullRequestNumber, absFeatureRef)
			if err := repo.RecordRSLEntryForReference(ctx, fmt.Sprintf("refs/pull/%d/head", pullRequestNumber), true, rslopts.WithOverrideRefName(absFeatureRef), rslopts.WithRecordLocalOnly()); err != nil {
				log.Default().Printf("Unable to create RSL entry: %v", err)
				return err
			}

			if err := gitRepo.Push("origin", []string{"refs/gittuf/*"}); err != nil {
				log.Default().Printf("Unable to push RSL: %v", err)
				return err
			}
		}

		// fallthrough to handle mergeable check
		fallthrough

	default:
		// Add checkrun for other PR actions
		// TODO: we can likely filter this on specific actions to not overload verification?

		hasPolicy, err := repo.HasPolicy()
		if err != nil {
			log.Default().Printf("Unable to check if policy exists: %v", err)
			return err
		}
		if hasPolicy {
			mergeable := false
			if _, err := repo.VerifyMergeable(ctx, baseRef, fmt.Sprintf("refs/pull/%d/head", pullRequestNumber), verifymergeableopts.WithBypassRSLForFeatureRef()); err == nil {
				// TODO: for now, we're not using the bool return
				mergeable = true
			} else {
				log.Default().Printf("VerifyMergeable failed: %v", err)
			}

			var conclusion, title, summary string
			if mergeable {
				conclusion = "success"
				title = "PR is mergeable!"
				summary = "Sufficient approvals have been submitted for the PR to be mergeable."
			} else {
				conclusion = "neutral"
				title = "PR is not mergeable"
				summary = "More approvals are necessary for the PR to be mergeable."
			}

			sha := event.GetPullRequest().GetHead().GetSHA()

			opts := github.CreateCheckRunOptions{
				Name:        "Verify gittuf policy",
				HeadSHA:     sha,
				ExternalID:  github.String(sha),
				Status:      github.String("completed"),
				Conclusion:  github.String(conclusion),
				StartedAt:   &github.Timestamp{Time: time.Now()},
				CompletedAt: &github.Timestamp{Time: time.Now()},
				Output: &github.CheckRunOutput{
					Title:   github.String(title),
					Summary: github.String(summary),
				},
			}

			client, err := getGitHubClient(transport, g.Params.GitHubURL)
			if err != nil {
				log.Default().Printf("Unable to create GitHub client: %v", err)
				return err
			}

			if _, _, err := client.Checks.CreateCheckRun(ctx, owner, repository, opts); err != nil {
				log.Default().Printf("Unable to create check run: %v", err)
				return err
			}
		}
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
	log.Default().Printf("Repository: %s/%s", owner, repository)

	pullRequestNumber := event.GetPullRequest().GetNumber()
	log.Default().Printf("Pull Request: %d", pullRequestNumber)

	installationID := event.GetInstallation().GetID()
	log.Default().Printf("Installation ID: %d", installationID)

	baseRef := event.GetPullRequest().GetBase().GetRef()

	// Who was the approver?
	reviewer := event.Review.GetUser()
	reviewerIdentifier := fmt.Sprintf("%s+%d", reviewer.GetLogin(), reviewer.GetID())

	cloneURL := event.GetPullRequest().GetBase().GetRepo().GetCloneURL()
	parsedURL, err := url.Parse(cloneURL)
	if err != nil {
		return err
	}

	transport := ghinstallation.NewFromAppsTransport(g.Transport, installationID)
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
	if _, err := git.PlainClone(localDirectory, false, &git.CloneOptions{URL: cloneURL, ReferenceName: plumbing.ReferenceName(baseRef)}); err != nil {
		log.Default().Printf("Unable to clone repository: %v", err)
		return err
	}

	repo, err := gittuf.LoadRepository(localDirectory)
	if err != nil {
		return err
	}
	gitRepo := repo.GetGitRepository()

	if err := gitRepo.Fetch("origin", []string{"refs/gittuf/*"}, true); err != nil {
		log.Default().Printf("Unable to fetch gittuf refs: %v", err)
		return err
	}

	// Fetch feature ref
	// We fetch using github's refs/pull/<number>/head ref as the feature ref
	// may be from a different repository
	refSpec := fmt.Sprintf("refs/pull/%d/head:refs/pull/%d/head", pullRequestNumber, pullRequestNumber)
	if err := gitRepo.FetchRefSpec("origin", []string{refSpec}); err != nil {
		log.Default().Printf("Unable to fetch feature branch: %v", err)
		return err
	}

	signer, err := gittuf.LoadSigner(repo, g.sshSigningKeyPath)
	if err != nil {
		return err
	}

	var message string
	switch event.GetAction() {
	case reviewTypeSubmitted:
		if event.GetReview().GetState() != reviewStateApproved {
			log.Default().Printf("Review from %s is not approval", reviewer.GetLogin())
			return nil
		}

		if err := repo.AddGitHubPullRequestApprover(ctx, signer, owner, repository, pullRequestNumber, event.GetReview().GetID(), reviewerIdentifier, true, githubopts.WithGitHubBaseURL(g.Params.GitHubURL), githubopts.WithGitHubTokenSource(transport), githubopts.WithRSLEntry()); err != nil {
			log.Default().Printf("Unable to create pull request approval attestation: %v", err)
			return err
		}

		message = fmt.Sprintf("Observed review from %s (@%s)", reviewerIdentifier, reviewer.GetLogin())

	case reviewTypeDismissed:
		if err := repo.DismissGitHubPullRequestApprover(ctx, signer, event.GetReview().GetID(), reviewerIdentifier, true, githubopts.WithGitHubBaseURL(g.Params.GitHubURL), githubopts.WithGitHubTokenSource(transport), githubopts.WithRSLEntry()); err != nil {
			log.Default().Printf("Unable to update pull request approval attestation with dismissal: %v", err)
			return err
		}

		message = fmt.Sprintf("Observed dismissal of review by %s (@%s)", reviewerIdentifier, reviewer.GetLogin())
	}

	if err := gitRepo.Push("origin", []string{"refs/gittuf/*"}); err != nil {
		log.Default().Printf("Unable to push gittuf refs: %v", err)
		return err
	}

	client, err := getGitHubClient(transport, g.Params.GitHubURL)
	if err != nil {
		return fmt.Errorf("unable to create GitHub client: %w", err)
	}
	if _, _, err := client.Issues.CreateComment(ctx, owner, repository, event.GetPullRequest().GetNumber(), &github.IssueComment{
		Body: &message,
	}); err != nil {
		return fmt.Errorf("unable to create GitHub comment: %w", err)
	}

	hasPolicy, err := repo.HasPolicy()
	if err != nil {
		log.Default().Printf("Unable to check if policy exists: %v", err)
		return err
	}
	if hasPolicy {
		mergeable := false
		if _, err := repo.VerifyMergeable(ctx, baseRef, fmt.Sprintf("refs/pull/%d/head", pullRequestNumber), verifymergeableopts.WithBypassRSLForFeatureRef()); err == nil {
			// TODO: for now, we're not using the bool return
			mergeable = true
		} else {
			log.Default().Printf("VerifyMergeable failed: %v", err)
		}

		var conclusion, title, summary string
		if mergeable {
			conclusion = "success"
			title = "PR is mergeable!"
			summary = "Sufficient approvals have been submitted for the PR to be mergeable."
		} else {
			conclusion = "neutral"
			title = "PR is not mergeable"
			summary = "More approvals are necessary for the PR to be mergeable."
		}

		sha := event.GetPullRequest().GetHead().GetSHA()

		opts := github.CreateCheckRunOptions{
			Name:        "Verify gittuf policy",
			HeadSHA:     sha,
			ExternalID:  github.String(sha),
			Status:      github.String("completed"),
			Conclusion:  github.String(conclusion),
			StartedAt:   &github.Timestamp{Time: time.Now()},
			CompletedAt: &github.Timestamp{Time: time.Now()},
			Output: &github.CheckRunOutput{
				Title:   github.String(title),
				Summary: github.String(summary),
			},
		}

		if _, _, err := client.Checks.CreateCheckRun(ctx, owner, repository, opts); err != nil {
			log.Default().Printf("Unable to create check run: %v", err)
			return err
		}
	}

	return nil
}

func getGitHubClient(transport *ghinstallation.Transport, githubURL string) (*github.Client, error) {
	client := github.NewClient(&http.Client{
		Transport: transport,
	})

	var err error
	if githubURL != DefaultGitHubURL {
		log.Default().Print("Enterprise instance found, creating enterprise client")
		log.Default().Printf("Instance url: %s", githubURL)
		base := fmt.Sprintf("%s/%s/%s/", githubURL, "api", "v3")
		upload := fmt.Sprintf("%s/%s/%s", githubURL, "api", "uploads")
		client, err = client.WithEnterpriseURLs(base, upload)
		if err != nil {
			return nil, err
		}
	}

	return client, nil
}
