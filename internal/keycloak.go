package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/chrisdd2/aws-login/appconfig"
)

type KeycloakRoleRef struct {
	ClientRole  bool   `json:"clientRole,omitempty"`
	Composite   bool   `json:"composite,omitempty"`
	ContainerId string `json:"containerId,omitempty"`
	Description string `json:"description,omitempty"`
	Id          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
}

type keycloakUser struct {
	ID        string            `json:"id"`
	Username  string            `json:"username"`
	Email     string            `json:"email"`
	FirstName string            `json:"firstName"`
	LastName  string            `json:"lastName"`
	Enabled   bool              `json:"enabled"`
	Roles     []KeycloakRoleRef `json:"roles,omitempty"`
}

type keycloakSyncer struct {
	baseURL      string
	realm        string
	clientID     string
	clientSecret string
	username     string
	password     string
	httpClient   *http.Client
	accessToken  string
	tokenExpiry  time.Time
}

func NewKeycloakSyncer(baseURL, realm, clientID, clientSecret, username, password string) *keycloakSyncer {
	return &keycloakSyncer{
		baseURL:      strings.TrimSuffix(baseURL, "/"),
		realm:        realm,
		clientID:     clientID,
		clientSecret: clientSecret,
		username:     username,
		password:     password,
		httpClient:   &http.Client{},
	}
}

func (k *keycloakSyncer) tokenURL() string {
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", k.baseURL, k.realm)
}

func (k *keycloakSyncer) apiURL(path string) string {
	return fmt.Sprintf("%s/admin/realms/%s/%s", k.baseURL, k.realm, path)
}

func (k *keycloakSyncer) ensureToken(ctx context.Context) error {
	if k.accessToken != "" && time.Now().Before(k.tokenExpiry.Add(-time.Minute)) {
		return nil
	}

	data := url.Values{
		"grant_type": {"password"},
		"client_id":  {k.clientID},
		"username":   {k.username},
		"password":   {k.password},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, k.tokenURL(), strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := k.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("execute token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token request failed: %d", resp.StatusCode)
	}

	var token struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return fmt.Errorf("decode token response: %w", err)
	}

	k.accessToken = token.AccessToken
	k.tokenExpiry = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)

	return nil
}

func (k *keycloakSyncer) get(ctx context.Context, path string) (*http.Response, error) {
	if err := k.ensureToken(ctx); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.apiURL(path), nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+k.accessToken)

	resp, err := k.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	return resp, nil
}

func (k *keycloakSyncer) getUsers(ctx context.Context) ([]keycloakUser, error) {
	resp, err := k.get(ctx, "users")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var users []keycloakUser
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return nil, fmt.Errorf("decode users: %w", err)
	}

	return users, nil
}

func (k *keycloakSyncer) getUserRoles(ctx context.Context, userID string) ([]KeycloakRoleRef, error) {
	resp, err := k.get(ctx, fmt.Sprintf("users/%s/role-mappings/realm/composite", userID))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var roles []KeycloakRoleRef
	if err := json.NewDecoder(resp.Body).Decode(&roles); err != nil {
		return nil, fmt.Errorf("decode role mappings: %w", err)
	}

	return roles, nil
}

func (k *keycloakSyncer) Users(ctx context.Context) ([]appconfig.User, error) {
	kcUsers, err := k.getUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("get keycloak users: %w", err)
	}

	users := make([]appconfig.User, 0, len(kcUsers))
	for _, u := range kcUsers {
		users = append(users, appconfig.User{
			Name:         u.Username,
			FriendlyName: buildFriendlyName(u.FirstName, u.LastName),
		})
	}

	return users, nil
}

func (k *keycloakSyncer) RolesForUser(ctx context.Context, username string) ([]string, error) {
	kcUsers, err := k.getUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("get keycloak users: %w", err)
	}

	var ret []string
	for _, u := range kcUsers {
		if u.Username != username {
			continue
		}
		roles, err := k.getUserRoles(ctx, u.ID)
		if err != nil {
			return nil, fmt.Errorf("get roles for user %s: %w", u.Username, err)
		}
		for _, role := range roles {
			ret = append(ret, role.Name)
		}
	}
	return ret, nil
}

func buildFriendlyName(firstName, lastName string) string {
	if firstName != "" && lastName != "" {
		return firstName + " " + lastName
	}
	if firstName != "" {
		return firstName
	}
	if lastName != "" {
		return lastName
	}
	return ""
}
