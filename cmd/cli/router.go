package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
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

func Router(
	ctx context.Context,
	auth *OpenIdService,
	rootUrl string,
	title string,
	tokenKey []byte,
	secureCookies bool,
	roles []internal.Role,
	stsCl *sts.Client,
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
		userInfo, err := auth.CallbackHandler(r)
		if err != nil {
			vals := url.Values{}
			vals.Add("error", "wrong_credentials")
			vals.Add("message", err.Error())
			http.Redirect(w, r, "/login?"+vals.Encode(), http.StatusSeeOther)
			return
		}

		validClaim := []string{}
		for _, g := range userInfo.Groups {
			_, ok := claimToRoleMap[g]
			if ok {
				validClaim = append(validClaim, g)
			}
		}
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
		http.Redirect(w, r, rootUrl, http.StatusSeeOther)
	})

	guard := LoggedInWrapper(tokenKey)

	index := guard.Wrap(indexPage(title, claimToRoleMap))
	r.HandleFunc("GET /", index)
	r.HandleFunc("POST /", index)
	r.HandleFunc("GET /role/{accountId}/{roleName}", guard.Wrap(assumeRole(stsCl, claimToRoleMap)))
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

func assumeRole(stsCl internal.AssumeRoleClient, rt RoleMap) AuthenticatedRoute {
	return func(w http.ResponseWriter, r *http.Request, uc *internal.UserClaims) {
		accountId := r.PathValue("accountId")
		roleName := r.PathValue("roleName")
		queryParams := r.URL.Query()
		redirectUrl := queryParams.Get("redirectUrl")

		var role *internal.Role
	outer:
		for _, c := range uc.Claims {
			roles := rt[c]
			for _, r := range roles {
				if r.AccountId == accountId && r.Name == roleName {
					role = r
					break outer
				}
			}
		}
		if role == nil {
			writeJsonError(w, http.StatusUnauthorized, "no access to role")
			return
		}

		ctx := r.Context()

		creds, err := internal.GenerateCredentials(ctx, stsCl, internal.RoleArn(accountId, roleName), uc.Username, time.Hour)
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

func indexPage(title string, rt RoleMap) AuthenticatedRoute {
	type roleView struct {
		Name       string
		AccountId  string
		ConsoleURL string
		CredURL    string
		Tags       map[string]string
	}

	type indexData struct {
		Title string
		User  *internal.UserClaims
		Roles []roleView
	}
	return func(w http.ResponseWriter, r *http.Request, uc *internal.UserClaims) {
		userRoles := []roleView{}
		for _, c := range uc.Claims {
			roles := rt[c]
			for _, role := range roles {
				basePath := fmt.Sprintf("/role/%s/%s", url.PathEscape(role.AccountId), url.PathEscape(role.Name))
				userRoles = append(userRoles, roleView{
					Name:       role.Name,
					AccountId:  role.AccountId,
					ConsoleURL: basePath + "?redirectUrl=" + url.QueryEscape(awsConsole),
					CredURL:    basePath + "?format=" + internal.CredentialFormatBash,
					Tags:       role.Tags,
				})
			}
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
	fmt.Fprintf(w, `{ "error" : "%s"}`, err)
}
