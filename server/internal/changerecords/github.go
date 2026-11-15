package changerecords

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"openxdr/server/ent"
)

// TokenCipher 封装绑定记录 ID 的凭据加解密，使 changerecords 保持叶子包依赖、不引入 hostimport。
type TokenCipher struct {
	Seal func(plain, binding string) ([]byte, error)
	Open func(ciphertext []byte, binding string) (string, error)
}

const (
	DefaultGitHubBaseURL = "https://api.github.com"
	ProviderGitHub       = "github"

	maxResponseBytes = 16 << 20
	maxTitleRunes    = 500
	maxBodyRunes     = 8000
	maxStoredFiles   = 300
	maxPathRunes     = 512
)

var (
	ErrVaultUnavailable = errors.New("未配置 HOST_CREDENTIAL_KEY，无法保存或解密访问令牌")
	repoSegmentRe       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
	hexSHARe            = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)
)

// CommitSummary 列表接口返回的单条提交概要。
type CommitSummary struct {
	SHA         string
	CommittedAt time.Time
}

// CommitDetail 单条提交的元数据、提交说明与改动文件路径（不含文件内容与 diff）。
type CommitDetail struct {
	SHA         string
	CommittedAt time.Time
	Author      string
	Title       string
	Body        string
	AllFiles    []string // 供确定性资产匹配使用的完整文件路径列表
	StoredFiles []string // 入库保留的前 maxStoredFiles 条路径
	FileCount   int
}

// CleanRepo 校验并归一化 GitHub 仓库标识（支持粘贴 https://github.com/owner/repo，统一存为 owner/repo）。
func CleanRepo(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	for _, prefix := range []string{"https://github.com/", "http://github.com/", "github.com/"} {
		if after, ok := strings.CutPrefix(strings.ToLower(s), prefix); ok {
			s = s[len(s)-len(after):]
			break
		}
	}
	s = strings.TrimSuffix(strings.TrimSuffix(s, "/"), ".git")
	owner, name, ok := strings.Cut(s, "/")
	if !ok || strings.Contains(name, "/") || owner == "." || owner == ".." || name == "." || name == ".." || !repoSegmentRe.MatchString(owner) || !repoSegmentRe.MatchString(name) {
		return "", errors.New("仓库格式须为 owner/repo")
	}
	return owner + "/" + name, nil
}

// CleanBranch 校验可选分支名（空表示仓库默认分支）。
func CleanBranch(raw string) (string, error) {
	b := strings.TrimSpace(raw)
	if b == "" {
		return "", nil
	}
	if utf8.RuneCountInString(b) > 128 || strings.Contains(b, "..") || strings.HasPrefix(b, "/") || strings.HasSuffix(b, "/") || strings.ContainsAny(b, " \t\r\n\\?*[~^:#@") {
		return "", errors.New("分支名无效")
	}
	return b, nil
}

func vaultBinding(id uuid.UUID) string {
	return "change-source:" + id.String()
}

// SealToken 使用 HOST_CREDENTIAL_KEY 绑定记录 ID 加密只读令牌，并生成脱敏尾号提示。
func SealToken(cipher *TokenCipher, id uuid.UUID, token string) ([]byte, string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, "", nil
	}
	if cipher == nil || cipher.Seal == nil {
		return nil, "", ErrVaultUnavailable
	}
	if len(token) > 1024 || strings.ContainsAny(token, "\r\n") {
		return nil, "", errors.New("访问令牌格式无效")
	}
	sealed, err := cipher.Seal(token, vaultBinding(id))
	if err != nil {
		return nil, "", err
	}
	hint := "••••"
	if len(token) >= 8 {
		hint = "••••" + token[len(token)-4:]
	}
	return sealed, hint, nil
}

// OpenToken 解开变更记录源保存的只读访问令牌。
func OpenToken(cipher *TokenCipher, src *ent.ChangeSource) (string, error) {
	if len(src.Secret) == 0 {
		return "", nil
	}
	if cipher == nil || cipher.Open == nil {
		return "", ErrVaultUnavailable
	}
	plain, err := cipher.Open(src.Secret, vaultBinding(src.ID))
	if err != nil {
		return "", fmt.Errorf("解密访问令牌失败: %w", err)
	}
	return plain, nil
}

type githubListEntry struct {
	SHA    string `json:"sha"`
	Commit struct {
		Author struct {
			Date *time.Time `json:"date"`
		} `json:"author"`
		Committer struct {
			Date *time.Time `json:"date"`
		} `json:"committer"`
	} `json:"commit"`
}

// githubDetailResponse 仅解码提交元数据、说明与文件路径，显式忽略 files[].patch 等代码内容字段。
type githubDetailResponse struct {
	SHA    string `json:"sha"`
	Commit struct {
		Message string `json:"message"`
		Author  struct {
			Name  string     `json:"name"`
			Email string     `json:"email"`
			Date  *time.Time `json:"date"`
		} `json:"author"`
		Committer struct {
			Name string     `json:"name"`
			Date *time.Time `json:"date"`
		} `json:"committer"`
	} `json:"commit"`
	Author *struct {
		Login string `json:"login"`
	} `json:"author"`
	Files []struct {
		Filename         string `json:"filename"`
		PreviousFilename string `json:"previous_filename"`
	} `json:"files"`
}

// listGitHubCommits 分页拉取指定时间以来的提交列表（GitHub 按提交时间倒序返回）。
func listGitHubCommits(ctx context.Context, client *http.Client, baseURL, repo, branch, token string, since time.Time, page, perPage int) ([]CommitSummary, error) {
	owner, name, err := splitRepo(repo)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("per_page", fmt.Sprintf("%d", perPage))
	q.Set("page", fmt.Sprintf("%d", page))
	if !since.IsZero() {
		q.Set("since", since.UTC().Format(time.RFC3339))
	}
	if branch != "" {
		q.Set("sha", branch)
	}
	endpoint := strings.TrimRight(baseURL, "/") + "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name) + "/commits?" + q.Encode()
	var raw []githubListEntry
	if err := doGitHubJSON(ctx, client, endpoint, token, &raw); err != nil {
		return nil, err
	}
	out := make([]CommitSummary, 0, len(raw))
	for _, item := range raw {
		if !hexSHARe.MatchString(item.SHA) {
			continue
		}
		ts := pickCommitTime(item.Commit.Committer.Date, item.Commit.Author.Date)
		if ts.IsZero() {
			continue
		}
		out = append(out, CommitSummary{SHA: strings.ToLower(item.SHA), CommittedAt: ts})
	}
	return out, nil
}

// getGitHubCommit 拉取单条提交的说明与改动文件路径（不读取、不存储文件内容与 diff）。
func getGitHubCommit(ctx context.Context, client *http.Client, baseURL, repo, sha, token string) (CommitDetail, error) {
	owner, name, err := splitRepo(repo)
	if err != nil {
		return CommitDetail{}, err
	}
	if !hexSHARe.MatchString(sha) {
		return CommitDetail{}, errors.New("提交 SHA 无效")
	}
	endpoint := strings.TrimRight(baseURL, "/") + "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name) + "/commits/" + url.PathEscape(sha)
	var raw githubDetailResponse
	if err := doGitHubJSON(ctx, client, endpoint, token, &raw); err != nil {
		return CommitDetail{}, err
	}
	ts := pickCommitTime(raw.Commit.Committer.Date, raw.Commit.Author.Date)
	if ts.IsZero() {
		return CommitDetail{}, errors.New("提交缺少有效时间戳")
	}
	title, body := splitCommitMessage(raw.Commit.Message)
	author := formatCommitAuthor(raw)

	var allFiles []string
	addPath := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		p = truncateRunes(p, maxPathRunes)
		if !slices.Contains(allFiles, p) {
			allFiles = append(allFiles, p)
		}
	}
	for _, f := range raw.Files {
		addPath(f.Filename)
		addPath(f.PreviousFilename)
	}
	stored := allFiles
	if len(stored) > maxStoredFiles {
		stored = stored[:maxStoredFiles]
	}
	fileCount := len(raw.Files)
	if fileCount == 0 && len(allFiles) > 0 {
		fileCount = len(allFiles)
	}
	return CommitDetail{
		SHA:         strings.ToLower(raw.SHA),
		CommittedAt: ts,
		Author:      author,
		Title:       title,
		Body:        body,
		AllFiles:    allFiles,
		StoredFiles: stored,
		FileCount:   fileCount,
	}, nil
}

func doGitHubJSON(ctx context.Context, client *http.Client, endpoint, token string, dst any) error {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "OpenXDR-ChangeSync/1.0")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("请求 GitHub 接口失败: %w", err)
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, maxResponseBytes+1)
	payload, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("读取 GitHub 响应失败: %w", err)
	}
	if len(payload) > maxResponseBytes {
		return errors.New("GitHub 响应超过体积上限")
	}
	if resp.StatusCode != http.StatusOK {
		var ghErr struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(payload, &ghErr)
		msg := sanitizeSingleLine(ghErr.Message, 120)
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		return fmt.Errorf("GitHub 返回 HTTP %d: %s", resp.StatusCode, msg)
	}
	if err := json.Unmarshal(payload, dst); err != nil {
		return fmt.Errorf("解析 GitHub 响应失败: %w", err)
	}
	return nil
}

func splitRepo(repo string) (string, string, error) {
	cleaned, err := CleanRepo(repo)
	if err != nil {
		return "", "", err
	}
	owner, name, _ := strings.Cut(cleaned, "/")
	return owner, name, nil
}

func pickCommitTime(committer, author *time.Time) time.Time {
	if committer != nil && !committer.IsZero() {
		return committer.UTC()
	}
	if author != nil && !author.IsZero() {
		return author.UTC()
	}
	return time.Time{}
}

func splitCommitMessage(msg string) (string, string) {
	msg = strings.ReplaceAll(msg, "\r\n", "\n")
	msg = strings.ReplaceAll(msg, "\r", "\n")
	msg = strings.TrimSpace(msg)
	first, rest, hasBody := strings.Cut(msg, "\n")
	title := truncateRunes(strings.TrimSpace(first), maxTitleRunes)
	if !hasBody {
		return title, ""
	}
	body := truncateRunes(strings.TrimSpace(rest), maxBodyRunes)
	return title, body
}

func formatCommitAuthor(raw githubDetailResponse) string {
	login := ""
	if raw.Author != nil {
		login = strings.TrimSpace(raw.Author.Login)
	}
	name := strings.TrimSpace(raw.Commit.Author.Name)
	if name == "" {
		name = strings.TrimSpace(raw.Commit.Committer.Name)
	}
	switch {
	case login != "" && name != "" && !strings.EqualFold(login, name):
		return truncateRunes(fmt.Sprintf("%s (%s)", login, name), 160)
	case login != "":
		return truncateRunes(login, 160)
	default:
		return truncateRunes(name, 160)
	}
}

func truncateRunes(s string, limit int) string {
	if limit <= 0 || utf8.RuneCountInString(s) <= limit {
		return s
	}
	var b strings.Builder
	count := 0
	for _, r := range s {
		if count >= limit {
			b.WriteRune('…')
			break
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}
