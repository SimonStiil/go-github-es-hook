package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

var (
	ErrEventNotSpecifiedToParse  = errors.New("no Event specified to parse")
	ErrInvalidHTTPMethod         = errors.New("invalid HTTP Method")
	ErrMissingGithubEventHeader  = errors.New("missing X-GitHub-Event Header")
	ErrMissingHubSignatureHeader = errors.New("missing X-Hub-Signature-256 Header")
	ErrEventNotFound             = errors.New("event not defined to be parsed")
	ErrParsingPayload            = errors.New("error parsing payload")
	ErrHMACVerificationFailed    = errors.New("HMAC verification failed")
)

const (
	PullRequestEvent Event = "pull_request"
)

type Event string

type Webhook struct {
	secret string
}

func (hook *Webhook) Parse(r *http.Request) (*PullRequest, []byte, error) {
	defer func() {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
	}()
	if r.Method != http.MethodPost {
		return nil, nil, ErrInvalidHTTPMethod
	}
	payload, err := io.ReadAll(r.Body)
	if err != nil || len(payload) == 0 {
		return nil, nil, ErrParsingPayload
	}
	if len(hook.secret) > 0 {
		signature := r.Header.Get("X-Hub-Signature-256")
		if len(signature) == 0 {
			return nil, payload, ErrMissingHubSignatureHeader
		}

		signature = strings.TrimPrefix(signature, "sha256=")

		mac := hmac.New(sha256.New, []byte(hook.secret))
		_, _ = mac.Write(payload)
		expectedMAC := hex.EncodeToString(mac.Sum(nil))

		if !hmac.Equal([]byte(signature), []byte(expectedMAC)) {
			return nil, payload, ErrHMACVerificationFailed
		}
	}
	event := r.Header.Get("X-GitHub-Event")
	if event == "" {
		return nil, payload, ErrMissingGithubEventHeader
	}
	gitHubEvent := Event(event)
	if gitHubEvent != PullRequestEvent {
		return nil, payload, ErrEventNotFound
	}
	switch gitHubEvent {
	case PullRequestEvent:
		pl := new(PullRequest)
		err = json.Unmarshal(payload, pl)
		return pl, payload, err
	default:
		return nil, payload, ErrEventNotSpecifiedToParse
	}
}

//Based on https://github.com/go-playground/webhooks/blob/master/github/github.go But api is out of data.

type Milestone struct {
	URL          string    `json:"url"`
	HTMLURL      string    `json:"html_url"`
	LabelsURL    string    `json:"labels_url"`
	ID           int64     `json:"id"`
	NodeID       string    `json:"node_id"`
	Number       int64     `json:"number"`
	State        string    `json:"state"`
	Title        string    `json:"title"`
	Description  string    `json:"description"`
	Creator      User      `json:"creator"`
	OpenIssues   int64     `json:"open_issues"`
	ClosedIssues int64     `json:"closed_issues"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	ClosedAt     time.Time `json:"closed_at"`
	DueOn        time.Time `json:"due_on"`
}

type User struct {
	Login      string `json:"login"`
	ID         int64  `json:"id"`
	NodeID     string `json:"node_id"`
	AvatarURL  string `json:"avatar_url"`
	GravatarID string `json:"gravatar_id"`
	Type       string `json:"type"`
	SiteAdmin  bool   `json:"site_admin"`
}
type Reference struct {
	Label string `json:"label"`
	Ref   string `json:"ref"`
	Sha   string `json:"sha"`
	User  User   `json:"user"`
	Repo  Repo   `json:"repo"`
}

type Repo struct {
	ID                        int64     `json:"id"`
	NodeID                    string    `json:"node_id"`
	Name                      string    `json:"name"`
	FullName                  string    `json:"full_name"`
	Owner                     User      `json:"owner"`
	Private                   bool      `json:"private"`
	HTMLURL                   string    `json:"html_url"`
	Description               string    `json:"description"`
	Fork                      bool      `json:"fork"`
	CreatedAt                 time.Time `json:"created_at"`
	UpdatedAt                 time.Time `json:"updated_at"`
	PushedAt                  time.Time `json:"pushed_at"`
	Homepage                  *string   `json:"homepage"`
	Size                      int64     `json:"size"`
	StargazersCount           int64     `json:"stargazers_count"`
	WatchersCount             int64     `json:"watchers_count"`
	Language                  *string   `json:"language"`
	HasIssues                 bool      `json:"has_issues"`
	HasDownloads              bool      `json:"has_downloads"`
	HasProjects               bool      `json:"has_projects"`
	HasWiki                   bool      `json:"has_wiki"`
	HasPages                  bool      `json:"has_pages"`
	HasDiscussions            bool      `json:"has_discussions"`
	ForksCount                int64     `json:"forks_count"`
	Archived                  bool      `json:"archived"`
	Disabled                  bool      `json:"disabled"`
	OpenIssuesCount           int64     `json:"open_issues_count"`
	AllowForking              bool      `json:"allow_forking"`
	IsTemplate                bool      `json:"is_template"`
	WebCommitSignoffRequired  bool      `json:"web_commit_signoff_required"`
	Topics                    []string  `json:"topics"`
	Visibility                string    `json:"visibility"`
	Forks                     int64     `json:"forks"`
	OpenIssues                int64     `json:"open_issues"`
	Watchers                  int64     `json:"watchers"`
	DefaultBranch             string    `json:"default_branch"`
	AllowSquashMerge          bool      `json:"allow_squash_merge"`
	AllowMergeCommit          bool      `json:"allow_merge_commit"`
	AllowRebaseMerge          bool      `json:"allow_rebase_merge"`
	AllowAutoMerge            bool      `json:"allow_auto_merge"`
	DeleteBranch_onMerge      bool      `json:"delete_branch_on_merge"`
	AllowUpdateBranch         bool      `json:"allow_update_branch"`
	UseSquashPrTitleAsDefault bool      `json:"use_squash_pr_title_as_default"`
	SquashMergeCommitMessage  string    `json:"squash_merge_commit_message"`
	SquashMergeCommit_title   string    `json:"squash_merge_commit_title"`
	MergeCommitMessage        string    `json:"merge_commit_message"`
	MergeCommitTitle          string    `json:"merge_commit_title"`
}

type PullRequest struct {
	Timestamp   time.Time `json:"timestamp"`
	Action      string    `json:"action"`
	Number      int64     `json:"number"`
	PullRequest struct {
		URL            string     `json:"url"`
		ID             int64      `json:"id"`
		NodeID         string     `json:"node_id"`
		Number         int64      `json:"number"`
		State          string     `json:"state"`
		Locked         bool       `json:"locked"`
		Title          string     `json:"title"`
		User           User       `json:"user"`
		Body           string     `json:"body"`
		CreatedAt      time.Time  `json:"created_at"`
		UpdatedAt      time.Time  `json:"updated_at"`
		ClosedAt       *time.Time `json:"closed_at"`
		MergedAt       *time.Time `json:"merged_at"`
		MergeCommitSha *string    `json:"merge_commit_sha"`
		Draft          bool       `json:"draft"`

		RequestedReviewers []User `json:"requested_reviewers,omitempty"`
		Labels             []struct {
			ID          int64  `json:"id"`
			NodeID      string `json:"node_id"`
			Description string `json:"description"`
			URL         string `json:"url"`
			Name        string `json:"name"`
			Color       string `json:"color"`
			Default     bool   `json:"default"`
		} `json:"labels"`
		Head                Reference `json:"head"`
		Base                Reference `json:"base"`
		AuthorAssociation   string    `json:"author_association"`
		Merged              bool      `json:"merged"`
		Mergeable           *bool     `json:"mergeable"`
		Rebaseable          bool      `json:"rebaseable"`
		MergeableState      string    `json:"mergeable_state"`
		MergedBy            *User     `json:"merged_by"`
		Comments            int64     `json:"comments"`
		ReviewComments      int64     `json:"review_comments"`
		MaintainerCanModify bool      `json:"maintainer_can_modify"`
		Commits             int64     `json:"commits"`
		Additions           int64     `json:"additions"`
		Deletions           int64     `json:"deletions"`
		ChangedFiles        int64     `json:"changed_files"`
	} `json:"pull_request"`
	Changes *struct {
		Title *struct {
			From string `json:"from"`
		} `json:"title"`
		Body *struct {
			From string `json:"from"`
		} `json:"body"`
	} `json:"changes"`
	Repository Repo `json:"repository"`
	Label      struct {
		ID          int64  `json:"id"`
		NodeID      string `json:"node_id"`
		Description string `json:"description"`
		URL         string `json:"url"`
		Name        string `json:"name"`
		Color       string `json:"color"`
		Default     bool   `json:"default"`
	} `json:"label"`
	Sender            User  `json:"sender"`
	Assignee          *User `json:"assignee"`
	RequestedReviewer *User `json:"requested_reviewer"`
	RequestedTeam     struct {
		Name        string `json:"name"`
		ID          int64  `json:"id"`
		NodeID      string `json:"node_id"`
		Slug        string `json:"slug"`
		Description string `json:"description"`
		Privacy     string `json:"privacy"`
		URL         string `json:"url"`
		Permission  string `json:"permission"`
	} `json:"requested_team"`
	Installation struct {
		ID int64 `json:"id"`
	} `json:"installation"`
}

func (pr *PullRequest) parse() ([]byte, error) {
	pr.Timestamp = time.Now()
	return json.Marshal(pr)
}
