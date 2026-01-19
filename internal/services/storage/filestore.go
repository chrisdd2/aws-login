package storage

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/chrisdd2/aws-login/appconfig"
	"github.com/google/uuid"
	"sigs.k8s.io/yaml"
)

type FileStore struct {
	InMemoryStore
	adminUser *appconfig.User
	s3Cl      *s3.Client
	cfg       *appconfig.AppConfig
	ev        fileEventer
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
	filename := filepath.Join(cfg.Storage.Directory, "events.json")
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	s.ev = fileEventer{f: f, w: bufio.NewWriter(f)}
	slog.Info("enabled", "eventer", "file")
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
	for _, ra := range s.RoleAccountAttachments {
		if ra.AccountName != accountName {
			continue
		}
		role, err := s.GetRole(ctx, ra.RoleName)
		if err != nil {
			continue
		}
		if !role.Disabled {
			roles = append(roles, role)
		}
	}
	return roles, nil
}
func (s *FileStore) ListRolePermissions(ctx context.Context, userName string, roleName string, accountName string) ([]appconfig.RoleUserAttachment, error) {
	user, err := s.GetUser(ctx, userName)
	if err != nil {
		return nil, fmt.Errorf("storage.GetUser: %w", err)
	}
	ats := []appconfig.RoleUserAttachment{}
	// superusers see the same roles as the admin user
	if user.Superuser {
		for _, at := range s.RoleAccountAttachments {
			// admins see any role that can actually be used
			ats = append(ats, appconfig.RoleUserAttachment{
				RoleUserAttachmentId: appconfig.RoleUserAttachmentId{
					Username:    userName,
					RoleName:    at.RoleName,
					AccountName: at.AccountName,
				},
				Permissions: appconfig.RolePermissionAll,
			})
		}
	}
	for _, at := range s.RoleUserAttachments {
		if matchOrEmpty(accountName, at.AccountName) && matchOrEmpty(roleName, at.RoleName) && matchOrEmpty(userName, at.Username) {
			ats = append(ats, at)
		}
	}
	return ats, nil
}
func (s *FileStore) GetInlinePolicy(ctx context.Context, id string) (*appconfig.Policy, error) {
	idx := slices.IndexFunc(s.Policies, func(acc appconfig.Policy) bool {
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
	friendlyName, _, _ := strings.Cut(s.cfg.Auth.AdminUsername, "@")
	user := &appconfig.User{
		Name:         s.cfg.Auth.AdminUsername,
		Superuser:    true,
		FriendlyName: friendlyName,
	}
	s.adminUser = user
	return user

}

func (s *FileStore) ListAccounts(ctx context.Context) ([]appconfig.Account, error) {
	ret := make([]appconfig.Account, 0, len(s.Accounts))
	for _, acc := range s.Accounts {
		ret = append(ret, acc)
	}
	return ret, nil
}
func (s *FileStore) ListUsers(ctx context.Context) ([]string, error) {
	ret := make([]string, 0, len(s.Users))
	for _, usr := range s.Users {
		ret = append(ret, usr.Name)
	}
	return ret, nil
}
func (s *FileStore) ListPolicies(ctx context.Context) ([]string, error) {
	ret := make([]string, 0, len(s.Policies))
	for _, p := range s.Policies {
		ret = append(ret, p.Id)
	}
	return ret, nil
}
func (s *FileStore) ListRoles(ctx context.Context) ([]string, error) {
	ret := make([]string, 0, len(s.Roles))
	for _, r := range s.Roles {
		ret = append(ret, r.Name)
	}
	return ret, nil
}

func (s *FileStore) GetPolicy(ctx context.Context, id string) (*appconfig.Policy, error) {
	idx := slices.IndexFunc(s.Policies, func(item appconfig.Policy) bool {
		return item.Id == id
	})
	if idx != -1 {
		return &s.Policies[idx], nil
	}
	return nil, ErrPolicyNotFound
}

func (s *FileStore) ListRoleAccountAttachments(ctx context.Context, roleName string, accountName string) ([]appconfig.RoleAccountAttachment, error) {
	return slices.Collect(func(yield func(appconfig.RoleAccountAttachment) bool) {
		for _, at := range s.RoleAccountAttachments {
			if matchOrEmpty(roleName, at.RoleName) && matchOrEmpty(accountName, at.AccountName) {
				if !yield(at) {
					break
				}
			}
		}
	}), nil
}

func (s *FileStore) ListRolePolicyAttachments(ctx context.Context, roleName string) ([]appconfig.RolePolicyAttachment, error) {
	return slices.Collect(func(yield func(appconfig.RolePolicyAttachment) bool) {
		for _, at := range s.RolePolicyAttachments {
			if matchOrEmpty(roleName, at.RoleName) {
				if !yield(at) {
					break
				}
			}
		}
	}), nil
}

func (s *FileStore) ListRoleUserAttachments(ctx context.Context, username string, roleName string, accountName string) ([]appconfig.RoleUserAttachment, error) {
	return slices.Collect(func(yield func(appconfig.RoleUserAttachment) bool) {
		for _, at := range s.RoleUserAttachments {
			if matchOrEmpty(roleName, at.RoleName) && matchOrEmpty(username, at.Username) && matchOrEmpty(accountName, at.AccountName) {
				if !yield(at) {
					break
				}
			}
		}
	}), nil
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
	s.Reset()
	s.Merge(ret, true)
	// reset admin
	s.adminUser = nil
	return nil
}

func (s *FileStore) Publish(ctx context.Context, eventType string, metadata map[string]string) error {
	slog.Info("event", "type", eventType, "metadata", metadata)
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
	type Event struct {
		Id       string            `json:"id,omitempty"`
		Time     time.Time         `json:"time"`
		Type     string            `json:"type,omitempty"`
		Metadata map[string]string `json:"metadata,omitempty"`
	}
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

func matchOrEmpty(a string, b string) bool {
	return a == "" || a == b
}
