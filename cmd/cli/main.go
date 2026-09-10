package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"net/http"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/chrisdd2/aws-login/internal"
	"gopkg.in/yaml.v3"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "provide a command")
		return
	}

	ctx := context.Background()
	if err := handleCommand(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func handleCommand(ctx context.Context) error {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return internal.WrapError(err, "aws.LoadDefaultConfig")
	}

	stsSvc := sts.NewFromConfig(cfg)
	whoami, err := stsSvc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return internal.WrapError(err, "sts.GetCallerIdentity")
	}

	command := os.Args[1]
	switch command {
	case "bootstrap":
		bootstrapFlags := flag.NewFlagSet("bootstrap", flag.ExitOnError)
		principalArn := bootstrapFlags.String("principal", "", "aws user arn that will be able to assume the bootstrap role in this account")
		if err := bootstrapFlags.Parse(os.Args[2:]); err != nil {
			return internal.WrapError(err, "bootstrapFlags.Parse")
		}
		if *principalArn == "" {
			return errors.New("must provide --principal")
		}
		fmt.Printf("bootstrapping in account [%s] as [%s]\n", *whoami.Account, *principalArn)
		iamSvc := iam.NewFromConfig(cfg)
		if err := internal.CreateBootstrapRole(ctx, iamSvc, *principalArn); err != nil {
			return internal.WrapError(err, "CreateBootstrapRole")
		}
		fmt.Printf("bootstrap role created [%s]\n", internal.BootstrapRoleArn(*whoami.Account))
		return nil
	case "web":
		ctx, cancelCtx := shutdownContext(context.Background())
		configDir := getOrDefault("CONFIG_FILE", "config")
		rt, err := loadConfig(configDir)
		if err != nil {
			return internal.WrapError(err, "loadConfig")
		}
		defer cancelCtx(errors.New("program exit"))
		webFlags := flag.NewFlagSet("web", flag.ExitOnError)
		addr := webFlags.String("address", ":8080", "address to listen for http requests")
		if err := webFlags.Parse(os.Args[2:]); err != nil {
			return internal.WrapError(err, "webFlags.Parse")
		}
		opts := OidcOptions{
			IssuerUrl:             getOrDie("OIDC_ISSUER_URL"),
			LogoutUrl:             os.Getenv("OIDC_LOGOUT_URL"),
			RedirectUrl:           getOrDie("OIDC_REDIRECT_URL"),
			ClientId:              getOrDie("OIDC_CLIENT_ID"),
			ClientSecret:          getOrDie("OIDC_SECRET"),
			Scopes:                strings.Split(os.Getenv("OIDC_SCOPES"), ","),
			GroupClaimsPath:       getOrDefault("OIDC_GROUP_CLAIMSPATH", "groups"),
			UsernameClaimsPath:    getOrDefault("OIDC_USERNAME_CLAIMSPATH", "username"),
			DisplayNameClaimsPath: getOrDefault("OIDC_DISPLAYNAME_CLAIMSPATH", "preferred_name"),
			SecureCookies:         getOrDefault("OIDC_SECURE_COOKIES", "false") == "true",
		}
		rootUrl := getOrDefault("BASE_URL", "/")
		tokenKey := getOrDie("ENCRYPTION_KEY")

		oidcSrv, err := NewOpenId(ctx, &opts)
		if err != nil {
			return internal.WrapError(err, "NewOpenID")
		}
		router := Router(ctx, oidcSrv, rootUrl, []byte(tokenKey), opts.SecureCookies, rt, stsSvc)

		srv := http.Server{Addr: *addr, Handler: router, ReadTimeout: time.Second * 30, WriteTimeout: time.Second * 30}
		go func() {
			err := srv.ListenAndServe()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		}()
		fmt.Printf("listening on [%s]\n", *addr)
		<-ctx.Done()
	default:
		fmt.Printf("unhandled command %s\n", command)
	}
	return nil
}

func shutdownContext(parent context.Context) (context.Context, context.CancelCauseFunc) {
	ctx, cancel := context.WithCancelCause(parent)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-ctx.Done():
			break
		case v := <-sigChan:
			cancel(fmt.Errorf("received %s signal", v))
			break
		}
		signal.Stop(sigChan)
	}()
	return ctx, cancel
}

func getOrDie(key string) string {
	v := os.Getenv(key)
	if v == "" {
		fmt.Printf("missing required [%s]\n", key)
		os.Exit(-1)
	}
	return v
}

func getOrDefault(key string, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func loadConfig(fp string) ([]internal.Role, error) {
	f, err := os.Open(fp)
	if err != nil {
		return nil, internal.WrapError(err, "os.Open")
	}
	defer f.Close()
	nfo, err := f.Stat()
	if err != nil {
		return nil, internal.WrapError(err, "f.Stat")
	}
	fileList := []string{}
	if nfo.IsDir() {
		entries, err := os.ReadDir(fp)
		if err != nil {
			return nil, internal.WrapError(err, "os.ReadDir")
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			fileList = append(fileList, filepath.Join(fp, e.Name()))
		}
	} else {
		fileList = []string{fp}
		f.Close()
	}
	ret := []internal.Role{}
	for _, filename := range fileList {
		f, err := os.Open(filename)
		if err != nil {
			return nil, internal.WrapError(err, "os.Open")
		}
		rt := struct {
			Roles []internal.Role `json:"roles,omitempty"`
		}{}
		ext := filepath.Ext(filename)
		var loadErr error
		switch ext {
		case ".yml":
		case ".yaml":
			if err := yaml.NewDecoder(f).Decode(&rt); err != nil {
				loadErr = internal.WrapError(err, "yaml.Decode")
			}
		case ".json":
			if err := json.NewDecoder(f).Decode(&rt); err != nil {
				loadErr = internal.WrapError(err, "json.Decode")
			}
		default:
			loadErr = internal.WrapError(errors.New(ext), "unknown extension")
		}
		f.Close()
		if err != nil {
			return nil, loadErr
		}
		ret = append(ret, rt.Roles...)
	}
	return ret, nil
}
