package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"log/slog"
	"net/http"
	"net/url"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/chrisdd2/aws-login/appconfig"
	"github.com/chrisdd2/aws-login/aws"
	"github.com/chrisdd2/aws-login/services"
	"github.com/chrisdd2/aws-login/webui"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/metrics"
	"github.com/google/uuid"
	"sigs.k8s.io/yaml"
)

func must(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
func must2[T any](a T, err error) T {
	if err != nil {
		log.Fatalln(err)
	}
	return a
}
func must3[T any, Y any](a T, b Y, err error) (T, Y) {
	if err != nil {
		log.Fatalln(err)
	}
	return a, b
}
func assert(cond bool, msg string) {
	if !cond {
		log.Fatalln(msg)
	}
}

func main() {
	appCfg := appconfig.AppConfig{}
	appCfg.SetEnvironmentVariablePrefix("APP_")
	must(appCfg.LoadDefaults())
	must(appCfg.LoadFromEnv())

	var logger *slog.Logger
	if appCfg.DevelopmentMode {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))
	} else {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{}))
	}
	slog.SetDefault(logger)

	appCfg.DebugPrint()

	ctx := context.Background()

	// AWS setup
	// allow different aws config for the aws user used for permissions in the other accounts
	awsContext := must2(appconfig.WithEnvContext(appCfg.PrefixEnv("ASSUMER_"), func() (awsSdk.Config, error) {
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return cfg, err
		}
		return cfg, nil
	}))

	stsClient := sts.NewFromConfig(awsContext)
	awsApi := must2(aws.NewAwsApi(ctx, stsClient))
	// check which user it is
	_, arn := must3(awsApi.WhoAmI(ctx))

	logger.Info("using", "assumer", arn)

	storageSvc := services.NewStaticStore(appCfg.AdminUsername)
	must(reloadConfig(ctx, &appCfg, storageSvc, awsContext))
	log.Printf("found [%d] accounts\n", len(storageSvc.Accounts))

	tokenSvc := services.NewToken(storageSvc, []byte(appCfg.SignKey))
	roleSvc := services.NewRoleService(storageSvc, awsApi)
	accSvc := services.NewAccountService(storageSvc, awsApi)
	idps := []services.AuthService{}
	if appCfg.GithubEnabled {
		idps = append(idps, &services.GithubService{ClientSecret: appCfg.GithubClientSecret, ClientId: appCfg.GithubClientId, AuthResponsePath: "/oauth2/github/idpresponse"})
		log.Println("[github] login enabled")
	}
	if appCfg.OpenIdEnabled {
		idps = append(idps, must2(services.NewOpenId(ctx, appCfg.OpenIdProviderUrl, appCfg.OpenIdRedirectUrl, appCfg.OpenIdClientId, appCfg.OpenIdClientSecret)))
		log.Println("[keycloak] login enabled")
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(metrics.Collector(metrics.CollectorOpts{
		Host:  false,
		Proto: true,
		Skip: func(r *http.Request) bool {
			return r.Method != "OPTIONS"
		},
	}))

	r.Handle("/metrics", metrics.Handler())

	r.Mount("/", webui.Router(tokenSvc, idps, roleSvc, accSvc, appCfg.AdminUsername, appCfg.AdminPassword, appCfg.RootUrl))

	logger.Info("listening", "address", appCfg.ListenAddr, "url", fmt.Sprintf("http:/%s", appCfg.ListenAddr))
	must(http.ListenAndServe(appCfg.ListenAddr, r))

}

func reloadConfig(ctx context.Context, appCfg *appconfig.AppConfig, storageSvc *services.Store, awsConfig awsSdk.Config) error {
	ret := &services.Store{}
	if appCfg.ConfigDirectory != "" {
		entries, err := os.ReadDir(appCfg.ConfigDirectory)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := filepath.Join(appCfg.ConfigDirectory, entry.Name())
			o := services.NewStaticStore("")
			log.Printf("loading file [%s]\n", name)
			f := must2(os.Open(name))
			if strings.HasSuffix(name, ".yml") {
				must(o.LoadYaml(f))
			} else if strings.HasSuffix(name, "json") {
				must(o.LoadJson(f))
			}
			f.Close()
			ret = ret.Merge(o, false)
		}
	} else if appCfg.ConfigUrl != "" {
		if !strings.HasPrefix(appCfg.ConfigUrl, "s3://") {
			return errors.New("only s3 urls support for config files")
		}
		s3Cl := s3.NewFromConfig(awsConfig)
		s3Url, err := url.Parse(appCfg.ConfigUrl)
		if err != nil {
			return err
		}
		bucket, path := s3Url.Hostname(), s3Url.Path
		pages := s3.NewListObjectsV2Paginator(s3Cl, &s3.ListObjectsV2Input{Bucket: &bucket, Prefix: &path})
		for pages.HasMorePages() {
			page, err := pages.NextPage(ctx)
			if err != nil {
				return err
			}
			for _, obj := range page.Contents {
				filedata, err := s3Cl.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: obj.Key})
				if err != nil {
					return err
				}
				filename := awsSdk.ToString(obj.Key)
				log.Printf("loading file [s3://%s/%s]\n", bucket, filename)
				o := services.NewStaticStore("")
				if strings.HasSuffix(filename, ".yml") {
					must(o.LoadYaml(filedata.Body))
				} else if strings.HasSuffix(filename, "json") {
					must(o.LoadJson(filedata.Body))
				}
				filedata.Body.Close()
				ret = ret.Merge(o, false)
			}
		}
	}
	storageSvc.Reset()
	storageSvc.Merge(ret, true)
	return nil
}

func generateDummyStore() {
	storageSvc := services.NewStaticStore("")
	attachments := []appconfig.RoleAttachment{}
	for i := range 10 {
		accountName := fmt.Sprintf("main-%d", i)
		if i == 0 {
			accountName = "main"
		}
		storageSvc.Accounts = append(storageSvc.Accounts, appconfig.Account{
			Name:         accountName,
			AwsAccountId: 992885815868 + i,
			Enabled:      true,
		})
		uniqueid := uuid.NewString()
		devRoleName := fmt.Sprintf("developer-role-%s", uniqueid)
		roRoleName := fmt.Sprintf("read-only-role-%s", uniqueid)
		storageSvc.Roles = append(storageSvc.Roles, appconfig.Role{
			Name:               devRoleName,
			MaxSessionDuration: time.Hour * 8,
			Enabled:            true,
			AssociatedAccounts: []string{accountName},
			ManagedPolicies:    []string{"arn:aws:iam::aws:policy/AdministratorAccess"},
		})
		storageSvc.Roles = append(storageSvc.Roles, appconfig.Role{
			Name:               roRoleName,
			MaxSessionDuration: time.Hour * 8,
			Enabled:            true,
			AssociatedAccounts: []string{accountName},
			ManagedPolicies:    []string{"arn:aws:iam::aws:policy/ReadOnlyAccess"},
		})
		attachments = append(attachments,
			appconfig.RoleAttachment{RoleName: devRoleName, AccountName: accountName, Permissions: []string{"console"}},
			appconfig.RoleAttachment{RoleName: roRoleName, AccountName: accountName, Permissions: []string{"credential", "console"}},
		)
	}
	storageSvc.Users = append(storageSvc.Users, appconfig.User{
		Name:      "chrisdd2",
		Email:     "chris.damianidis2@gmail.com",
		Superuser: true,
		Roles:     attachments,
	})
	f := must2(os.Create(".config/test_bench.yml"))
	defer f.Close()
	f.Write(must2(yaml.Marshal(&storageSvc)))
}
