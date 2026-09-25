package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/chrisdd2/aws-login/internal"
)

var ErrNotSupported = errors.New("not supported")

const awsConsole = "https://console.aws.amazon.com/"

const authCookie = "aws-login-cookie"

const returnCookie = "aws-login-return"

func validAwsUrl(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return false
	}
	host := u.Hostname()
	return host == "aws.amazon.com" || strings.HasSuffix(host, ".aws.amazon.com")
}

var multiSessionLabel = regexp.MustCompile(`^[0-9]{12}-[a-z0-9]+$`)

func normalizeAwsUrl(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return s
	}
	labels := strings.Split(u.Host, ".")
	if len(labels) > 5 && multiSessionLabel.MatchString(strings.ToLower(labels[0])) {
		u.Host = strings.Join(labels[1:], ".")
		return u.String()
	}
	return s
}

func safeReturnPath(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && !strings.HasPrefix(p, "/\\")
}

func loginErrorString(queryParams url.Values) string {
	if queryParams.Get("fromLogout") != "" {
		return "logged out"
	}
	errorValue := queryParams.Get("error")
	if errorValue == "" {
		return ""
	}
	switch errorValue {
	case "user_not_found":
		return fmt.Sprintf("User [%s] has no accessible role", queryParams.Get("username"))
	case "invalid_cookie":
		return "Authentication cookie is invalid, log out and retry"
	case "wrong_credentials":
		return fmt.Sprintf("Authentication failed [%s].\nContact an administrator", queryParams.Get("message"))
	case "token_expired":
		return "Login session expired, log in again"
	default:
		return fmt.Sprintf("Internal server error [%s]", queryParams.Get("message"))
	}
}

var ErrNoCookie = errors.New("no auth cookie")
var ErrTokenParse = errors.New("invalid_cookie")
var ErrTokenExpired = errors.New("token_expired")

func getLogin(key []byte, r *http.Request) (*internal.UserClaims, error) {
	cookie, err := r.Cookie(authCookie)
	if err != nil {
		return nil, ErrNoCookie
	}
	token, err := internal.ParseToken(r.Context(), key, cookie.Value)
	if err != nil {
		internal.Debugf("getLogin: failed to parse token: %s", err)
		return nil, ErrTokenParse
	}
	if token.ExpiresAt.Time.Before(time.Now().UTC()) {
		internal.Debugf("getLogin: token for %q expired at %s", token.Username, token.ExpiresAt.Time)
		return nil, ErrTokenExpired
	}
	internal.Debugf("getLogin: user %q logged in with groups %v", token.Username, token.Claims)
	return token, nil
}

type AuthenticatedRoute func(http.ResponseWriter, *http.Request, *internal.UserClaims)

type LoggedInWrapper struct {
	key    []byte
	secure bool
}

func (l *LoggedInWrapper) Wrap(h AuthenticatedRoute) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := getLogin(l.key, r)
		if err != nil {
			if r.Method == http.MethodGet {
				http.SetCookie(w, &http.Cookie{
					Name:     returnCookie,
					Value:    r.URL.RequestURI(),
					MaxAge:   600,
					HttpOnly: true,
					Secure:   l.secure,
					SameSite: http.SameSiteLaxMode,
					Path:     "/",
				})
			}
			if err == ErrNoCookie {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			vals := url.Values{}
			vals.Add("error", err.Error())
			http.Redirect(w, r, "/login?"+vals.Encode(), http.StatusSeeOther)
			return
		}
		h(w, r, token)
	}
}

type RoleMap map[string][]*internal.Role

func (rt RoleMap) RolesFor(claims []string) iter.Seq[*internal.Role] {
	return func(yield func(*internal.Role) bool) {
		for _, c := range claims {
			for _, r := range rt[c] {
				if !yield(r) {
					return
				}
			}
		}
	}
}

func (rt RoleMap) Find(claims []string, accountId, roleName string) *internal.Role {
	for r := range rt.RolesFor(claims) {
		if r.AccountId == accountId && r.Name == roleName {
			return r
		}
	}
	return nil
}

func Router(
	ctx context.Context,
	auth *OpenIdService,
	rootUrl string,
	title string,
	tokenKey []byte,
	secureCookies bool,
	roles []internal.Role,
	stsCl internal.AssumeRoleClient,
	ssmClients SsmClientFactory,
) *http.ServeMux {

	claimToRoleMap := RoleMap{}
	for _, r := range roles {
		for _, c := range r.Claim {
			claimToRoleMap[c] = append(claimToRoleMap[c], &r)
		}
	}

	if rootUrl == "" {
		rootUrl = "/"
	}
	r := http.ServeMux{}

	r.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		queryParams := r.URL.Query()
		if errMsg := loginErrorString(queryParams); errMsg != "" {
			w.Header().Add("Content-Type", "text/html; charset=utf-8")
			if err := templates.ExecuteTemplate(w, "login", struct {
				Title string
				Error string
			}{Title: title, Error: errMsg}); err != nil {
				writeJsonError(w, http.StatusInternalServerError, err.Error())
			}
			return
		}
		_, err := getLogin(tokenKey, r)
		if err == nil {
			// logged in already
			http.Redirect(w, r, rootUrl, http.StatusTemporaryRedirect)
			return
		}
		auth.Login(w, r)
	})

	r.HandleFunc("GET /oauth2/callback", func(w http.ResponseWriter, r *http.Request) {
		internal.Debugf("oauth2/callback: exchanging code for token")
		userInfo, err := auth.CallbackHandler(r)
		if err != nil {
			internal.Debugf("oauth2/callback: CallbackHandler failed: %s", err)
			vals := url.Values{}
			vals.Add("error", "wrong_credentials")
			vals.Add("message", err.Error())
			http.Redirect(w, r, "/login?"+vals.Encode(), http.StatusSeeOther)
			return
		}
		internal.Debugf("oauth2/callback: user %q (%s) logged in with groups %v", userInfo.Username, userInfo.DisplayName, userInfo.Groups)

		validClaim := []string{}
		for _, g := range userInfo.Groups {
			_, ok := claimToRoleMap[g]
			if ok {
				validClaim = append(validClaim, g)
			}
		}
		internal.Debugf("oauth2/callback: groups matching a known role: %v", validClaim)
		if len(validClaim) == 0 {
			fmt.Fprintf(os.Stderr, "user %s with groups [%s] not matching\n", userInfo.DisplayName, userInfo.Groups)
			vals := url.Values{}
			vals.Add("error", "user_not_found")
			vals.Add("username", userInfo.Username)
			http.Redirect(w, r, "/login?"+vals.Encode(), http.StatusSeeOther)
			return
		}

		signed, err := internal.SignToken(tokenKey, userInfo.Username, validClaim, userInfo.IdToken, 8*time.Hour)
		if err != nil {
			internal.Debugf("oauth2/callback: SignToken failed: %s", err)
			writeJsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     authCookie,
			Value:    signed,
			HttpOnly: true,
			Secure:   secureCookies,
			SameSite: http.SameSiteLaxMode,
			Path:     "/",
		})
		target := rootUrl
		if c, err := r.Cookie(returnCookie); err == nil {
			if safeReturnPath(c.Value) {
				target = c.Value
			}
			http.SetCookie(w, &http.Cookie{Name: returnCookie, Path: "/", MaxAge: -1})
		}
		internal.Debugf("oauth2/callback: session cookie set for %q, redirecting to %s", userInfo.Username, target)
		http.Redirect(w, r, target, http.StatusSeeOther)
	})

	guard := LoggedInWrapper{key: tokenKey, secure: secureCookies}

	index := guard.Wrap(indexPage(title, claimToRoleMap))
	r.HandleFunc("GET /", index)
	r.HandleFunc("POST /", index)
	r.HandleFunc("GET /role/{accountId}/{roleName}", guard.Wrap(assumeRole(stsCl, claimToRoleMap)))
	r.HandleFunc("POST /role/{accountId}/{roleName}/link", guard.Wrap(createLink(tokenKey, rootUrl, claimToRoleMap)))
	r.HandleFunc("GET /role/{accountId}/{roleName}/ssm/regions", guard.Wrap(listSsmRegions(stsCl, ssmClients, claimToRoleMap)))
	r.HandleFunc("GET /role/{accountId}/{roleName}/ssm/instances", guard.Wrap(listSsmInstances(stsCl, ssmClients, claimToRoleMap)))
	r.HandleFunc("GET /role/{accountId}/{roleName}/ssm/{instanceId}", guard.Wrap(ssmSession(stsCl, claimToRoleMap)))
	r.HandleFunc("GET /{token}", guard.Wrap(followLink(tokenKey, stsCl, claimToRoleMap)))
	r.HandleFunc("GET /logout", func(w http.ResponseWriter, r *http.Request) {
		uc, err := getLogin(tokenKey, r)
		if err != nil {
			// no valid login, go to main
			http.Redirect(w, r, rootUrl, http.StatusTemporaryRedirect)
			return
		}
		cookie, _ := r.Cookie(authCookie)
		if cookie != nil {
			cookie.MaxAge = -1
			http.SetCookie(w, cookie)
		}
		logoutRedirect := auth.PostLogoutRedirectUrl("/login", url.Values{"fromLogout": {"1"}})
		internal.Debugf("logout: user %q logging out, post_logout_redirect_uri=%s", uc.Username, logoutRedirect)
		http.Redirect(w, r, auth.LogoutUrl(logoutRedirect, uc.IdpToken), http.StatusTemporaryRedirect)
	})

	return &r
}

func assumeRole(stsCl internal.AssumeRoleClient, rt RoleMap) AuthenticatedRoute {
	return func(w http.ResponseWriter, r *http.Request, uc *internal.UserClaims) {
		accountId := r.PathValue("accountId")
		roleName := r.PathValue("roleName")
		queryParams := r.URL.Query()
		redirectUrl := queryParams.Get("redirectUrl")

		role := rt.Find(uc.Claims, accountId, roleName)
		if role == nil {
			internal.Debugf("assumeRole: user %q with groups %v has no access to %s/%s", uc.Username, uc.Claims, accountId, roleName)
			writeJsonError(w, http.StatusUnauthorized, "no access to role")
			return
		}

		if redirectUrl != "" {
			consoleRedirect(w, r, stsCl, uc, accountId, roleName, awsConsole)
			return
		}

		creds, err := internal.GenerateCredentials(r.Context(), stsCl, internal.RoleArn(accountId, roleName), uc.Username, time.Hour)
		if err != nil {
			writeJsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		formatType := queryParams.Get("format")
		// it might end up being json, but its untyped
		w.Header().Add("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(creds.Format(formatType)))
	}

}

func consoleRedirect(w http.ResponseWriter, r *http.Request, stsCl internal.AssumeRoleClient, uc *internal.UserClaims, accountId string, roleName string, destination string) {
	ctx := r.Context()
	creds, err := internal.GenerateCredentials(ctx, stsCl, internal.RoleArn(accountId, roleName), uc.Username, time.Hour)
	if err != nil {
		writeJsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	signed, err := internal.GenerateSignedUrl(ctx, creds, destination, time.Hour*8)
	if err != nil {
		writeJsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	http.Redirect(w, r, signed, http.StatusTemporaryRedirect)
}

func createLink(tokenKey []byte, rootUrl string, rt RoleMap) AuthenticatedRoute {
	return func(w http.ResponseWriter, r *http.Request, uc *internal.UserClaims) {
		accountId := r.PathValue("accountId")
		roleName := r.PathValue("roleName")
		if rt.Find(uc.Claims, accountId, roleName) == nil {
			internal.Debugf("createLink: user %q with groups %v has no access to %s/%s", uc.Username, uc.Claims, accountId, roleName)
			writeJsonError(w, http.StatusUnauthorized, "no access to role")
			return
		}
		destination := normalizeAwsUrl(strings.TrimSpace(r.FormValue("url")))
		if !validAwsUrl(destination) {
			writeJsonError(w, http.StatusBadRequest, "url must be an https aws.amazon.com address")
			return
		}
		token, err := internal.SignLinkToken(tokenKey, accountId, roleName, destination)
		if err != nil {
			writeJsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			Url string `json:"url"`
		}{Url: strings.TrimSuffix(rootUrl, "/") + "/" + token})
	}
}

func followLink(tokenKey []byte, stsCl internal.AssumeRoleClient, rt RoleMap) AuthenticatedRoute {
	return func(w http.ResponseWriter, r *http.Request, uc *internal.UserClaims) {
		link, err := internal.ParseLinkToken(tokenKey, r.PathValue("token"))
		if err != nil {
			internal.Debugf("followLink: invalid token: %s", err)
			writeJsonError(w, http.StatusNotFound, "not found")
			return
		}
		if rt.Find(uc.Claims, link.Account, link.Role) == nil {
			internal.Debugf("followLink: user %q with groups %v has no access to %s/%s", uc.Username, uc.Claims, link.Account, link.Role)
			writeJsonError(w, http.StatusUnauthorized, "no access to role")
			return
		}
		destination := normalizeAwsUrl(link.Url)
		if !validAwsUrl(destination) {
			writeJsonError(w, http.StatusBadRequest, "invalid destination url")
			return
		}
		consoleRedirect(w, r, stsCl, uc, link.Account, link.Role, destination)
	}
}

type SsmClientFactory func(creds internal.AwsCredentials, region string) (internal.SsmClient, internal.Ec2Client)

const ssmPageSize = 20

func ssmRegionParam(r *http.Request) (string, bool) {
	region := r.URL.Query().Get("region")
	if region == "" {
		return internal.DefaultSsmRegion, true
	}
	return region, internal.ValidSsmRegion(region)
}

func ssmRole(w http.ResponseWriter, r *http.Request, rt RoleMap, uc *internal.UserClaims) (*internal.Role, string, bool) {
	role := rt.Find(uc.Claims, r.PathValue("accountId"), r.PathValue("roleName"))
	if role == nil {
		writeJsonError(w, http.StatusUnauthorized, "no access to role")
		return nil, "", false
	}
	if !role.SsmEnabled {
		writeJsonError(w, http.StatusNotFound, "ssm not enabled for role")
		return nil, "", false
	}
	region, ok := ssmRegionParam(r)
	if !ok {
		writeJsonError(w, http.StatusBadRequest, "invalid region")
		return nil, "", false
	}
	return role, region, true
}

func ssmRoleClients(w http.ResponseWriter, r *http.Request, stsCl internal.AssumeRoleClient, ssmClients SsmClientFactory, role *internal.Role, uc *internal.UserClaims, region string) (internal.SsmClient, internal.Ec2Client, bool) {
	creds, err := internal.GenerateCredentials(r.Context(), stsCl, internal.RoleArn(role.AccountId, role.Name), uc.Username, time.Hour)
	if err != nil {
		writeJsonError(w, http.StatusInternalServerError, err.Error())
		return nil, nil, false
	}
	ssmCl, ec2Cl := ssmClients(creds, region)
	return ssmCl, ec2Cl, true
}

func listSsmRegions(stsCl internal.AssumeRoleClient, ssmClients SsmClientFactory, rt RoleMap) AuthenticatedRoute {
	return func(w http.ResponseWriter, r *http.Request, uc *internal.UserClaims) {
		role, region, ok := ssmRole(w, r, rt, uc)
		if !ok {
			return
		}
		_, ec2Cl, ok := ssmRoleClients(w, r, stsCl, ssmClients, role, uc, region)
		if !ok {
			return
		}
		regions, err := internal.ListEnabledRegions(r.Context(), ec2Cl)
		if err != nil {
			writeJsonError(w, http.StatusBadGateway, err.Error())
			return
		}
		def := internal.DefaultSsmRegion
		if !slices.Contains(regions, def) && len(regions) > 0 {
			def = regions[0]
		}
		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			Regions []string `json:"regions"`
			Default string   `json:"default"`
		}{Regions: regions, Default: def})
	}
}

func listSsmInstances(stsCl internal.AssumeRoleClient, ssmClients SsmClientFactory, rt RoleMap) AuthenticatedRoute {
	return func(w http.ResponseWriter, r *http.Request, uc *internal.UserClaims) {
		role, region, ok := ssmRole(w, r, rt, uc)
		if !ok {
			return
		}
		ssmCl, ec2Cl, ok := ssmRoleClients(w, r, stsCl, ssmClients, role, uc, region)
		if !ok {
			return
		}
		instances, next, err := internal.ListSsmInstances(r.Context(), ssmCl, ec2Cl, r.URL.Query().Get("next"), ssmPageSize)
		if err != nil {
			writeJsonError(w, http.StatusBadGateway, err.Error())
			return
		}
		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			Region    string                 `json:"region"`
			Instances []internal.SsmInstance `json:"instances"`
			Next      string                 `json:"next"`
		}{Region: region, Instances: instances, Next: next})
	}
}

func ssmSession(stsCl internal.AssumeRoleClient, rt RoleMap) AuthenticatedRoute {
	return func(w http.ResponseWriter, r *http.Request, uc *internal.UserClaims) {
		role, region, ok := ssmRole(w, r, rt, uc)
		if !ok {
			return
		}
		instanceId := r.PathValue("instanceId")
		if !internal.ValidInstanceId.MatchString(instanceId) {
			writeJsonError(w, http.StatusBadRequest, "invalid instance id")
			return
		}
		consoleRedirect(w, r, stsCl, uc, role.AccountId, role.Name, internal.SsmSessionUrl(region, instanceId))
	}
}

func indexPage(title string, rt RoleMap) AuthenticatedRoute {
	type roleView struct {
		Name       string
		AccountId  string
		ConsoleURL string
		CredURL    string
		LinkURL    string
		SsmURL     string
		Tags       map[string]string
	}

	type indexData struct {
		Title string
		User  *internal.UserClaims
		Roles []roleView
	}
	return func(w http.ResponseWriter, r *http.Request, uc *internal.UserClaims) {
		userRoles := []roleView{}
		for role := range rt.RolesFor(uc.Claims) {
			basePath := fmt.Sprintf("/role/%s/%s", url.PathEscape(role.AccountId), url.PathEscape(role.Name))
			view := roleView{
				Name:       role.Name,
				AccountId:  role.AccountId,
				ConsoleURL: basePath + "?redirectUrl=" + url.QueryEscape(awsConsole),
				CredURL:    basePath + "?format=" + internal.CredentialFormatBash,
				LinkURL:    basePath + "/link",
				Tags:       role.Tags,
			}
			if role.SsmEnabled {
				view.SsmURL = basePath + "/ssm"
			}
			userRoles = append(userRoles, view)
		}
		sort.Slice(userRoles, func(i, j int) bool {
			if userRoles[i].AccountId == userRoles[j].AccountId {
				return userRoles[i].Name < userRoles[j].Name
			}
			return userRoles[i].AccountId < userRoles[j].AccountId
		})

		w.Header().Add("Content-Type", "text/html; charset=utf-8")
		if err := templates.ExecuteTemplate(w, "index", indexData{User: uc, Roles: userRoles, Title: title}); err != nil {
			writeJsonError(w, http.StatusInternalServerError, err.Error())
		}
	}
}

func writeJsonError(w http.ResponseWriter, statusCode int, err string) {
	fmt.Fprintf(os.Stderr, "Error %d: %s\n", statusCode, err)
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{Error: err})
}
