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
		return "Your account has no accessible role"
	case "invalid_cookie":
		return "Authentication cookie is invalid, log out and retry"
	case "wrong_credentials":
		return "Authentication failed.\nContact an administrator"
	case "token_expired":
		return "Login session expired, log in again"
	default:
		return "Internal server error"
	}
}

var ErrNoCookie = errors.New("no auth cookie")
var ErrTokenParse = errors.New("invalid_cookie")
var ErrTokenExpired = errors.New("token_expired")
var ErrTokenStale = errors.New("token_stale")

func getLogin(key []byte, refresh time.Duration, r *http.Request) (*internal.UserClaims, error) {
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
	if refresh > 0 && (token.IssuedAt == nil || token.IssuedAt.Time.Add(refresh).Before(time.Now().UTC())) {
		internal.Debugf("getLogin: token for %q is older than %s, re-authenticating", token.Username, refresh)
		return nil, ErrTokenStale
	}
	internal.Debugf("getLogin: user %q logged in with groups %v", token.Username, token.Claims)
	return token, nil
}

type AuthenticatedRoute func(http.ResponseWriter, *http.Request, *internal.UserClaims)

type LoggedInWrapper struct {
	key     []byte
	refresh time.Duration
	secure  bool
}

func (l *LoggedInWrapper) Wrap(h AuthenticatedRoute) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := getLogin(l.key, l.refresh, r)
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
			if err == ErrNoCookie || err == ErrTokenStale {
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
	sessionRefresh time.Duration,
	roles []internal.Role,
	stsCl internal.AssumeRoleClient,
) http.Handler {

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
				writeInternalError(w, http.StatusInternalServerError, err)
			}
			return
		}
		_, err := getLogin(tokenKey, sessionRefresh, r)
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
			fmt.Fprintf(os.Stderr, "oauth2/callback: login failed: %s\n", err)
			vals := url.Values{}
			vals.Add("error", "wrong_credentials")
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
			http.Redirect(w, r, "/login?"+vals.Encode(), http.StatusSeeOther)
			return
		}

		signed, err := internal.SignToken(tokenKey, userInfo.Username, validClaim, userInfo.IdToken, 8*time.Hour)
		if err != nil {
			writeInternalError(w, http.StatusInternalServerError, err)
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

	guard := LoggedInWrapper{key: tokenKey, refresh: sessionRefresh, secure: secureCookies}

	index := guard.Wrap(indexPage(title, claimToRoleMap))
	r.HandleFunc("GET /", index)
	r.HandleFunc("POST /", index)
	r.HandleFunc("GET /role/{accountId}/{roleName}", guard.Wrap(assumeRole(stsCl, claimToRoleMap)))
	r.HandleFunc("GET /logout", func(w http.ResponseWriter, r *http.Request) {
		uc, err := getLogin(tokenKey, 0, r)
		http.SetCookie(w, &http.Cookie{Name: authCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: secureCookies, SameSite: http.SameSiteLaxMode})
		if err != nil {
			http.Redirect(w, r, rootUrl, http.StatusTemporaryRedirect)
			return
		}
		logoutRedirect := auth.PostLogoutRedirectUrl("/login", url.Values{"fromLogout": {"1"}})
		internal.Debugf("logout: user %q logging out, post_logout_redirect_uri=%s", uc.Username, logoutRedirect)
		http.Redirect(w, r, auth.LogoutUrl(logoutRedirect, uc.IdpToken), http.StatusTemporaryRedirect)
	})

	return securityHeaders(&r, secureCookies)
}

func securityHeaders(h http.Handler, secure bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := w.Header()
		hdr.Set("Cache-Control", "no-store")
		hdr.Set("X-Content-Type-Options", "nosniff")
		hdr.Set("X-Frame-Options", "DENY")
		hdr.Set("Content-Security-Policy", "frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
		hdr.Set("Referrer-Policy", "same-origin")
		if secure {
			hdr.Set("Strict-Transport-Security", "max-age=31536000")
		}
		h.ServeHTTP(w, r)
	})
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
			// validate url
			redirectUrl = normalizeAwsUrl(redirectUrl)
			if !validAwsUrl(redirectUrl) {
				writeJsonError(w, http.StatusBadRequest, "invalid redirect url")
				return
			}
			consoleRedirect(w, r, stsCl, uc, role, redirectUrl)
			return
		}

		creds, err := internal.GenerateCredentials(r.Context(), stsCl, internal.RoleArn(accountId, roleName), uc.Username, role.MaxSessionDuration)
		if err != nil {
			writeInternalError(w, http.StatusInternalServerError, err)
			return
		}
		formatType := queryParams.Get("format")
		// it might end up being json, but its untyped
		w.Header().Add("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(creds.Format(formatType)))
	}

}

func consoleRedirect(w http.ResponseWriter, r *http.Request, stsCl internal.AssumeRoleClient, uc *internal.UserClaims, role *internal.Role, destination string) {
	ctx := r.Context()
	creds, err := internal.GenerateCredentials(ctx, stsCl, internal.RoleArn(role.AccountId, role.Name), uc.Username, role.MaxSessionDuration)
	if err != nil {
		writeInternalError(w, http.StatusInternalServerError, err)
		return
	}

	signed, err := internal.GenerateSignedUrl(ctx, creds, destination, time.Hour*8)
	if err != nil {
		writeInternalError(w, http.StatusInternalServerError, err)
		return
	}
	http.Redirect(w, r, signed, http.StatusTemporaryRedirect)
}

func indexPage(title string, rt RoleMap) AuthenticatedRoute {
	type linkView struct {
		Href        string
		Url         string
		Description string
	}

	type roleView struct {
		Name       string
		AccountId  string
		ConsoleURL string
		CredURL    string
		Links      []linkView
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
				Tags:       role.Tags,
			}
			for _, l := range role.Links {
				view.Links = append(view.Links, linkView{
					Href:        basePath + "?redirectUrl=" + url.QueryEscape(l.Url),
					Url:         l.Url,
					Description: l.Description,
				})
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
			writeInternalError(w, http.StatusInternalServerError, err)
		}
	}
}

func writeInternalError(w http.ResponseWriter, statusCode int, err error) {
	fmt.Fprintf(os.Stderr, "Error %d: %s\n", statusCode, err)
	writeJsonBody(w, statusCode, http.StatusText(statusCode))
}

func writeJsonError(w http.ResponseWriter, statusCode int, err string) {
	fmt.Fprintf(os.Stderr, "Error %d: %s\n", statusCode, err)
	writeJsonBody(w, statusCode, err)
}

func writeJsonBody(w http.ResponseWriter, statusCode int, err string) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{Error: err})
}
