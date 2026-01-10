package storage

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/chrisdd2/aws-login/appconfig"
	"github.com/google/uuid"
	"sigs.k8s.io/yaml"
)

type FileStore struct {
	Users     []appconfig.User         `json:"users,omitempty"`
	Accounts  []appconfig.Account      `json:"accounts,omitempty"`
	Roles     []appconfig.Role         `json:"roles,omitempty"`
	Policies  []appconfig.InlinePolicy `json:"policies,omitempty"`
	adminUser *appconfig.User
	s3Cl      *s3.Client
	cfg       *appconfig.AppConfig
	ev        Eventer
}

func (s *FileStore) Reset() {
	s.Users = nil
	s.Accounts = nil
	s.Roles = nil
	s.Policies = nil
}

func (s *FileStore) Merge(o *FileStore, inPlace bool) *FileStore {
	cfg := s.cfg
	if cfg == nil {
		cfg = o.cfg
	}
	s3Cl := s.s3Cl
	if s3Cl == nil {
		s3Cl = o.s3Cl
	}
	var ret *FileStore
	if inPlace {
		ret = s
		s.cfg = cfg
		s.s3Cl = s3Cl
	} else {
		ret = &FileStore{cfg: cfg, s3Cl: s3Cl}
	}
	ret.Users = slices.Concat(s.Users, o.Users)
	ret.Accounts = slices.Concat(s.Accounts, o.Accounts)
	ret.Roles = slices.Concat(s.Roles, o.Roles)
	ret.Policies = slices.Concat(s.Policies, o.Policies)
	return ret
}
func (s *FileStore) LoadYaml(r io.Reader) error {
	buf, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(buf, s, yaml.DisallowUnknownFields)
}
func (s *FileStore) LoadJson(r io.Reader) error {
	return json.NewDecoder(r).Decode(&s)
}

func NewStaticStore(ctx context.Context, cfg *appconfig.AppConfig, awsCfg aws.Config) (*FileStore, error) {
	s := &FileStore{cfg: cfg, s3Cl: s3.NewFromConfig(awsCfg)}
	if strings.HasPrefix(cfg.Storage.Directory, "s3://") {
		s3Url, err := url.Parse(cfg.Storage.Directory)
		if err != nil {
			return nil, err
		}
		bucket, key := s3Url.Hostname(), strings.TrimPrefix(s3Url.Path, "/")
		s3Eventer, err := NewS3Eventer(s3.NewFromConfig(awsCfg), bucket, key)
		if err != nil {
			return nil, err
		}
		go s3Eventer.CommitLoop(ctx, time.Minute, 100, time.Minute*10)
		s.ev = s3Eventer
		slog.Info("enabled", "eventer", "s3")
	} else {
		filename := filepath.Join(cfg.Storage.Directory, "events.json")
		f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			return nil, err
		}
		s.ev = &fileEventer{f: f, w: bufio.NewWriter(f)}
		slog.Info("enabled", "eventer", "file")
	}
	return s, nil
}

func (s *FileStore) GetAccount(ctx context.Context, name string) (*appconfig.Account, error) {
	idx := slices.IndexFunc(s.Accounts, func(acc appconfig.Account) bool {
		return name == acc.Name
	})
	if idx != -1 {
		return &s.Accounts[idx], nil
	}
	return nil, ErrAccountNotFound
}

func (s *FileStore) ListRolesForAccount(ctx context.Context, accountName string) ([]*appconfig.Role, error) {
	roles := []*appconfig.Role{}
	acc, err := s.GetAccount(ctx, accountName)
	if err != nil {
		return nil, err
	}
	for _, role := range s.Roles {
		if slices.Contains(acc.Roles, role.Name) {
			roles = append(roles, &role)
		}
	}
	return roles, nil
}
func (s *FileStore) ListRolePermissions(ctx context.Context, userName string, roleName string, accountName string) ([]appconfig.RoleUserAttachment, error) {
	user, err := s.GetUser(ctx, userName)
	if err != nil {
		return nil, fmt.Errorf("storage.GetUser: %w", err)
	}
	attachments := user.Roles
	// superusers see the same roles as the admin user
	if user.Superuser {
		attachments = s.createAdminUser().Roles
	}
	ats := []appconfig.RoleUserAttachment{}
	for _, at := range attachments {
		if (accountName == "" || at.AccountName == accountName) && (roleName == "" || at.RoleName == roleName) {
			ats = append(ats, at)
		}
	}
	return ats, nil
}
func (s *FileStore) GetInlinePolicy(ctx context.Context, id string) (*appconfig.InlinePolicy, error) {
	idx := slices.IndexFunc(s.Policies, func(acc appconfig.InlinePolicy) bool {
		return id == acc.Id
	})
	if idx != -1 {
		return &s.Policies[idx], nil
	}
	return nil, ErrPolicyNotFound
}
func (s *FileStore) GetUser(ctx context.Context, id string) (*appconfig.User, error) {
	if id == s.cfg.Auth.AdminUsername {
		return s.createAdminUser(), nil
	}
	idx := slices.IndexFunc(s.Users, func(acc appconfig.User) bool {
		return id == acc.Name
	})
	if idx != -1 {
		return &s.Users[idx], nil
	}
	return nil, ErrUserNotFound
}

func (s *FileStore) GetRole(ctx context.Context, name string) (*appconfig.Role, error) {
	idx := slices.IndexFunc(s.Roles, func(acc appconfig.Role) bool {
		return name == acc.Name
	})
	if idx != -1 {
		return &s.Roles[idx], nil
	}
	return nil, ErrRoleNotFound
}

func (s *FileStore) createAdminUser() *appconfig.User {
	if s.adminUser != nil {
		return s.adminUser
	}
	// make a role attachment for every role available
	attachments := []appconfig.RoleUserAttachment{}
	for _, acc := range s.Accounts {
		for _, role := range acc.Roles {
			attachments = append(attachments,
				appconfig.RoleUserAttachment{
					RoleName:    role,
					AccountName: acc.Name,
					Permissions: []string{appconfig.RolePermissionConsole, appconfig.RolePermissionCredentials}})
		}
	}
	friendlyName, _, _ := strings.Cut(s.cfg.Auth.AdminUsername, "@")

	user := &appconfig.User{
		Name:         s.cfg.Auth.AdminUsername,
		Superuser:    true,
		FriendlyName: friendlyName,
		Roles:        attachments,
	}
	s.adminUser = user
	return user

}

func (s *FileStore) ListAccounts(ctx context.Context) ([]*appconfig.Account, error) {
	ret := make([]*appconfig.Account, 0, len(s.Accounts))
	for _, acc := range s.Accounts {
		ret = append(ret, &acc)
	}
	return ret, nil
}

func (s *FileStore) Reload(ctx context.Context) error {
	ret := &FileStore{}
	sgDir := s.cfg.Storage.Directory
	if strings.HasPrefix(sgDir, "s3://") {
		// its s3
		s3Url, err := url.Parse(sgDir)
		if err != nil {
			return err
		}
		bucket, path := s3Url.Hostname(), strings.TrimPrefix(s3Url.Path, "/")
		pages := s3.NewListObjectsV2Paginator(s.s3Cl, &s3.ListObjectsV2Input{Bucket: &bucket, Prefix: &path})
		for pages.HasMorePages() {
			page, err := pages.NextPage(ctx)
			if err != nil {
				return err
			}
			for _, obj := range page.Contents {
				name := aws.ToString(obj.Key)
				if !strings.HasSuffix(name, ".yml") {
					continue
				}
				resp, err := s.s3Cl.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: obj.Key})
				if err != nil {
					return err
				}
				o := FileStore{}
				slog.Info("load_config", "type", "s3", "filename", fmt.Sprintf("s3://%s/%s", bucket, name))
				if err := o.LoadYaml(resp.Body); err != nil {
					resp.Body.Close()
					return err
				}
				resp.Body.Close()
				ret = ret.Merge(&o, false)
			}
		}
	} else {
		entries, err := os.ReadDir(sgDir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			name := filepath.Join(sgDir, entry.Name())
			if entry.IsDir() {
				continue
			}
			if !strings.HasSuffix(name, ".yml") {
				continue
			}
			o := FileStore{}
			f, err := os.Open(name)
			if err != nil {
				return err
			}
			defer f.Close()
			slog.Info("load_config", "type", "filesystem", "filename", name)
			if err := o.LoadYaml(f); err != nil {
				return err
			}
			ret = ret.Merge(&o, false)
		}
	}
	if err := ret.Validate(ctx); err != nil {
		return err
	}
	s.Reset()
	s.Merge(ret, true)
	// reset admin
	s.adminUser = nil
	return nil
}

func duplicates[T any](arr []T, selector func(a T) string) error {
	visited := map[string]struct{}{}
	for _, a := range arr {
		v := selector(a)
		_, ok := visited[v]
		if !ok {
			visited[v] = struct{}{}
			continue
		}
		return fmt.Errorf("found duplicate [%s]", v)
	}
	return nil
}

func (s *FileStore) Validate(ctx context.Context) error {
	verifyAccount := func(ctx context.Context, acc appconfig.Account) error {
		name := strings.TrimSpace(acc.Name)
		if name == "" {
			return fmt.Errorf("account name must not be empty")
		}
		awsAccountId, err := strconv.ParseInt(acc.AwsAccountId, 10, 64)
		if err != nil {
			return err
		}
		if awsAccountId < 100000000000 || awsAccountId > 999999999999 {
			// aws account is a 12digit number
			return fmt.Errorf("invalid account number [%s]", acc.AwsAccountId)
		}
		// verify that all roles referred exist
		for _, role := range acc.Roles {
			_, err := s.GetRole(ctx, role)
			if err != nil {
				return fmt.Errorf("missing role [%s]", role)
			}
		}
		return nil
	}
	verifyUser := func(ctx context.Context, u appconfig.User) error {
		name := strings.TrimSpace(u.Name)
		if name == "" {
			return fmt.Errorf("username must not be empty")
		}
		for _, a := range u.Roles {
			_, err := s.GetRole(ctx, a.RoleName)
			if err != nil {
				return fmt.Errorf("missing role [%s]", a.RoleName)
			}
			_, err = s.GetAccount(ctx, a.AccountName)
			if err != nil {
				return fmt.Errorf("missing account [%s]", a.AccountName)
			}
		}
		return nil
	}
	verifyRole := func(ctx context.Context, r appconfig.Role) error {
		name := strings.TrimSpace(r.Name)
		if name == "" {
			return fmt.Errorf("rolename must not be empty")
		}
		for _, v := range r.Policies {
			_, err := s.GetInlinePolicy(ctx, v)
			if err != nil {
				return fmt.Errorf("missing policy [%s]", v)
			}
		}
		return nil
	}
	verifyPolicy := func(p appconfig.InlinePolicy) error {
		if strings.TrimSpace(p.Id) == "" {
			return fmt.Errorf("policy id must not be empty")
		}
		if strings.TrimSpace(p.Document) == "" {
			return fmt.Errorf("policy document must not be empty")
		}
		return nil
	}
	err := errors.Join(
		duplicates(s.Roles, func(r appconfig.Role) string { return r.Name }),
		duplicates(s.Accounts, func(r appconfig.Account) string { return r.Name }),
		duplicates(s.Users, func(r appconfig.User) string { return r.Name }),
		duplicates(s.Policies, func(r appconfig.InlinePolicy) string { return r.Id }),
	)
	if err != nil {
		return err
	}
	// verify that roles and accounts to match
	errs := []error{}
	for _, acc := range s.Accounts {
		// validate account id
		err := verifyAccount(ctx, acc)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: [%w]", acc.Name, err))
			continue
		}
	}
	for _, user := range s.Users {
		err := verifyUser(ctx, user)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: [%w]", user.Name, err))
			continue
		}
	}
	for _, role := range s.Roles {
		err := verifyRole(ctx, role)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: [%w]", role.Name, err))
			continue
		}
	}
	for _, policy := range s.Policies {
		err := verifyPolicy(policy)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: [%w]", policy.Id, err))
			continue
		}
	}
	return errors.Join(errs...)
}

func (s *FileStore) Display(ctx context.Context) (map[string]string, error) {
	marshal := func(v any) string {
		data, err := yaml.Marshal(v)
		if err != nil {
			return ""
		}
		return string(data)
	}
	data := map[string]string{
		"Accounts": marshal(s.Accounts),
		"Roles":    marshal(s.Roles),
		"Users":    marshal(s.Users),
		"Policies": marshal(s.Policies),
	}
	return data, nil
}

func (s *FileStore) Publish(ctx context.Context, eventType string, metadata map[string]string) error {
	return s.ev.Publish(ctx, eventType, metadata)
}

type fileEventer struct {
	f *os.File
	w *bufio.Writer
}

func (f *fileEventer) Close() {
	f.w.Flush()
	f.f.Close()
}
func (f *fileEventer) Publish(ctx context.Context, eventType string, metadata map[string]string) error {
	b, err := json.Marshal(Event{
		Id:       uuid.NewString(),
		Time:     time.Now().UTC(),
		Type:     eventType,
		Metadata: metadata,
	})
	if err != nil {
		return err
	}
	f.w.Write(b)
	f.w.WriteByte('\n')
	return f.w.Flush()
}

type s3Eventer struct {
	s3             *s3.Client
	bucket         string
	key            string
	lastCommitTime time.Time
	buffered       []Event
	bufferedLock   sync.Mutex
}

func NewS3Eventer(s3Cl *s3.Client, bucket string, key string) (*s3Eventer, error) {
	return &s3Eventer{
		s3:           s3Cl,
		bucket:       bucket,
		key:          key,
		bufferedLock: sync.Mutex{},
	}, nil
}

func (s *s3Eventer) Publish(ctx context.Context, eventType string, metadata map[string]string) error {
	s.bufferedLock.Lock()
	s.buffered = append(s.buffered, Event{
		Id:       uuid.NewString(),
		Time:     time.Now().UTC(),
		Type:     eventType,
		Metadata: metadata,
	})
	s.bufferedLock.Unlock()
	return nil
}

func (s *s3Eventer) CommitLoop(ctx context.Context, commitInternal time.Duration, commitNumEventThreshold int, commitTimeWindow time.Duration) {
	done := ctx.Done()
	ticker := time.Tick(commitInternal)
	for {
		select {
		case <-done:
			return
		case <-ticker:
			if err := s.commit(ctx, commitNumEventThreshold, commitTimeWindow); err != nil {
				slog.Info("s3eventer", "commit_error", err)
			}
		}
	}
}
func (s *s3Eventer) commit(ctx context.Context, commitThreshold int, commitWindow time.Duration) error {
	if len(s.buffered) == 0 {
		return nil
	}
	if len(s.buffered) < commitThreshold && s.lastCommitTime.Sub(time.Now().UTC()) < commitWindow {
		return nil
	}
	buf := bytes.Buffer{}
	commitTime := time.Now().UTC()
	enc := json.NewEncoder(&buf)
	s.bufferedLock.Lock()
	events := s.buffered
	for _, ev := range events {
		enc.Encode(ev)
		buf.WriteByte('\n')
	}
	s.buffered = nil
	s.lastCommitTime = commitTime
	s.bufferedLock.Unlock()
	s3Key := fmt.Sprintf("%s-%d", s.key, commitTime.UnixMilli())
	if _, err := s.s3.PutObject(ctx, &s3.PutObjectInput{Body: &buf, Key: &s3Key, Bucket: &s.bucket}); err != nil {
		return err
	}
	return nil
}
