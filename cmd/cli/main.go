package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"log/slog"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
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

	fmt.Printf("bootstrapping in account [%s] as [%s]", *whoami.Account, *whoami.Arn)

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
		iamSvc := iam.NewFromConfig(cfg)
		if err := CreateBootstrapRole(ctx, iamSvc, *principalArn); err != nil {
			fmt.Println(err)
		} else {
			fmt.Println("bootstrap role created [%s]", bootstrapRoleArn(*whoami.Account))
		}
		return
	case "web":
		webFlags := flag.NewFlagSet("web", flag.ExitOnError)
		addr := webFlags.String("address", ":8080", "address to listen for http requests")
		if err := webFlags.Parse(os.Args[2:]); err != nil {
			fmt.Println(err)
			return
		}
		log.Println(*addr)
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
			cancel(fmt.Errorf("%s signal", v))
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
