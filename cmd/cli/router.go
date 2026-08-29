package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/chrisdd2/aws-login/internal"
)

var ErrNotSupported = errors.New("not supported")

const awsConsole = "https://console.aws.amazon.com/"

const authCookie = "aws-login-cookie"

func loginErrorString(queryParams url.Values) string {
	errorValue := queryParams.Get("error")
	if errorValue == "" {
		return ""
	}
	switch errorValue {
	case "invalid_cookie":
		return "Authentication cookie is invalid, log out and retry"
	case "user_not_found":
		return fmt.Sprintf("User [%s] not found in database.\nContact an administrator", queryParams.Get("username"))
	case "wrong_credentials":
		return "Invalid username/password"
	default:
		return fmt.Sprintf("Interval server error [%s]", queryParams.Get("message"))
	}
}

var ErrNoCookie = errors.New("no auth cookie")
var ErrTokenParse = errors.New("invalid auth token")
var ErrTokenExpired = errors.New("expired auth token")

func getLogin(key []byte, r *http.Request) (*internal.UserClaims, error) {
	cookie, err := r.Cookie(authCookie)
	if err != nil {
		return nil, ErrNoCookie
	}
	token, err := internal.ParseToken(r.Context(), key, cookie.Value)
	if err != nil {
		return nil, ErrTokenParse
	}
	if token.ExpiresAt.Time.Before(time.Now().UTC()) {
		return nil, ErrTokenExpired
	}
	return token, nil
}

type AuthenticatedRoute func(http.ResponseWriter, *http.Request, *internal.UserClaims)

type LoggedInWrapper []byte

func (l *LoggedInWrapper) Wrap(h AuthenticatedRoute) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := getLogin(*l, r)
		if err != nil {
			vals := url.Values{}
			vals.Add("error", err.Error())
			http.Redirect(w, r, "/login?"+vals.Encode(), http.StatusSeeOther)
			return
		}
		h(w, r, token)
	}
}

func Router(
	ctx context.Context,
	auth *OpenIdService,
	rootUrl string,
	tokenKey []byte,
	secureCookies bool,
	rt *internal.RuntimeConfig,
	stsCl *sts.Client,
) *http.ServeMux {

	if rootUrl == "" {
		rootUrl = "/"
	}
	r := http.ServeMux{}

	r.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		_, err := getLogin(tokenKey, r)
		if err == nil {
			// logged in already
			http.Redirect(w, r, rootUrl, http.StatusTemporaryRedirect)
			return
		}
		auth.Login(w, r)
	})

	guard := LoggedInWrapper(tokenKey)

	indexPage := guard.Wrap(indexPage())
	r.HandleFunc("GET /", indexPage)
	r.HandleFunc("POST /", indexPage)
	r.HandleFunc("GET /role/{accountid}/{roleName}", guard.Wrap(assumeRole(stsCl, rt)))
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
		http.Redirect(w, r, auth.LogoutUrl(rootUrl, uc.IdpToken), http.StatusTemporaryRedirect)
	})

	return &r
}

func assumeRole(stsCl internal.AssumeRoleClient, rt *internal.RuntimeConfig) AuthenticatedRoute {
	return func(w http.ResponseWriter, r *http.Request, uc *internal.UserClaims) {
		accountId := r.PathValue("accountId")
		roleName := r.PathValue("roleName")
		queryParams := r.URL.Query()
		redirectUrl := queryParams.Get("redirectUrl")

		if !rt.HasIamRoleAccess(accountId, roleName, uc.Principals...) {
			writeJsonError(w, http.StatusUnauthorized, "no access to role")
			return
		}
		awsAccountId, iamRoleName, ok := rt.RoleDetails(accountId, roleName)
		if !ok {
			writeJsonError(w, http.StatusInternalServerError, "role doesn't exist")
			return
		}
		ctx := r.Context()

		cfg, err := internal.AssumeRoleConfig(ctx, stsCl, bootstrapRoleArn(awsAccountId), "aws-login", time.Minute*15)
		if err != nil {
			writeJsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		assumedSts := sts.NewFromConfig(cfg)
		creds, err := internal.GenerateCredentials(ctx, assumedSts, roleArn(awsAccountId, iamRoleName), uc.Username, time.Hour)
		if err != nil {
			writeJsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if redirectUrl != "" {
			url, err := internal.GenerateSignedUrl(ctx, creds, awsConsole, time.Hour*8)
			if err != nil {
				writeJsonError(w, http.StatusInternalServerError, err.Error())
				return
			}
			http.Redirect(w, r, url, http.StatusTemporaryRedirect)
			return
		}
		formatType := queryParams.Get("format")
		// it might end up being json, but its untyped
		w.Header().Add("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(creds.Format(formatType)))
	}

}
func indexPage() func(w http.ResponseWriter, r *http.Request, uc *internal.UserClaims) {
	return func(w http.ResponseWriter, r *http.Request, uc *internal.UserClaims) {
	}
}

func writeJsonError(w http.ResponseWriter, statusCode int, err string) {
	fmt.Fprintf(os.Stderr, "Error %d: %s\n", statusCode, err)
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	fmt.Fprintf(w, `{ "error" : "%s"}`, err)
}