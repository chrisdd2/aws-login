package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"log/slog"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/chrisdd2/aws-login/internal"
	"gopkg.in/yaml.v3"
)

func main() {
	if len(os.Args) < 2 {
		log.Println("provide a command")
		return
	}

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalln(err)
	}

	stsSvc := sts.NewFromConfig(cfg)
	whoami, err := stsSvc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		log.Fatalln(err)
	}

	command := os.Args[1]
	switch command {
	case "bootstrap":
		bootstrapFlags := flag.NewFlagSet("bootstrap", flag.ExitOnError)
		principalArn := bootstrapFlags.String("principal", "", "aws user arn that will be able to assume the bootstrap role in this account")
		if err := bootstrapFlags.Parse(os.Args[2:]); err != nil {
			fmt.Println(err)
			return
		}
		if *principalArn == "" {
			fmt.Println("must provide --principal")
			return
		}
		fmt.Printf("bootstrapping in account [%s] as [%s]\n", *whoami.Account, *principalArn)
		iamSvc := iam.NewFromConfig(cfg)
		if err := CreateBootstrapRole(ctx, iamSvc, *principalArn); err != nil {
			fmt.Println(err)
		} else {
			fmt.Printf("bootstrap role created [%s]\n", bootstrapRoleArn(*whoami.Account))
		}
		return
	case "web":
		ctx, cancelCtx := shutdownContext(context.Background())
		configDir := getOrDefault("CONFIG_FILE", "config")
		rt, err := loadConfig(configDir)
		if err != nil {
			log.Fatalln(err)
		}
		defer cancelCtx(errors.New("program exit"))
		webFlags := flag.NewFlagSet("web", flag.ExitOnError)
		addr := webFlags.String("address", ":8080", "address to listen for http requests")
		if err := webFlags.Parse(os.Args[2:]); err != nil {
			fmt.Println(err)
			return
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
			fmt.Println(err)
			return
		}

		router := Router(context.Background(), oidcSrv, rootUrl, []byte(tokenKey), opts.SecureCookies, rt, stsSvc)
		srv := http.Server{Addr: *addr, Handler: router}
		go func() {
			err := srv.ListenAndServe()
			if err != nil {
				log.Println(err)
			}
		}()
		<-ctx.Done()
	default:
		fmt.Printf("unhandled command %s\n", command)
	}

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

type gracefullServer struct {
	Name   string
	Server http.Server
}

func (g *gracefullServer) Listen(cancel context.CancelCauseFunc) {
	slog.Info(g.Name, "address", g.Server.Addr, "url", fmt.Sprintf("http://%s", g.Server.Addr))
	err := g.Server.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Info("http", "error", err.Error())
		cancel(err)
	}
}
func (g *gracefullServer) Shutdown(ctx context.Context) {
	if err := g.Server.Shutdown(ctx); err != nil {
		slog.Info(g.Name, "shutdown_error", err.Error())
	}
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

func loadConfig(fp string) (*internal.RuntimeConfig, error) {

	if strings.HasPrefix(fp, "http://") || strings.HasPrefix(fp, "https://") {
		// its a url
		resp, err := http.Get(fp)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			buf, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("loadConfig http error %d: %s", resp.StatusCode, string(buf))
		}
		rt := internal.RuntimeConfig{}
		if err := json.NewDecoder(resp.Body).Decode(&rt); err != nil {
			return nil, err
		}
		return &rt, nil
	}

	f, err := os.Open(fp)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	nfo, err := f.Stat()
	if err != nil {
		return nil, err
	}
	fileList := []string{}
	if nfo.IsDir() {
		entries, err := os.ReadDir(fp)
		if err != nil {
			return nil, err
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
	ret := internal.RuntimeConfig{}
	for _, filename := range fileList {
		f, err := os.Open(filename)
		if err != nil {
			return nil, err
		}
		rt := internal.RuntimeConfig{}
		ext := filepath.Ext(filename)
		switch ext {
		case ".yml":
		case ".yaml":
			err = yaml.NewDecoder(f).Decode(&rt)
		case ".json":
			err = json.NewDecoder(f).Decode(&rt)
		default:
			return nil, fmt.Errorf("unknown extension %s", ext)
		}
		f.Close()
		if err != nil {
			return nil, err
		}
		ret.Accounts = append(ret.Accounts, rt.Accounts...)
		ret.Policies = append(ret.Policies, rt.Policies...)
		ret.Principals = append(ret.Principals, rt.Principals...)
		ret.Roles = append(ret.Roles, rt.Roles...)
		ret.SsmActions = append(ret.SsmActions, rt.SsmActions...)
	}
	return &ret, nil
}
