package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/chrisdd2/aws-login/internal/blob"
	"github.com/chrisdd2/session-manager-plugin/session"
)

const (
	DocumentPortForward       = "AWS-StartPortForwardingSession"
	DocumentPortForwardToHost = "AWS-StartPortForwardingSessionToRemoteHost"
	DocumentShell             = "AWS-StartInteractiveCommand"
)

type Parameters struct {
	AccessKeyId     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
	SessionToken    string `json:"session_token,omitempty"`
	Operation       string `json:"operation,omitempty"`
	Reason          string `json:"reason,omitempty"`
	Text            string `json:"text,omitempty"`
	Target          string `json:"target,omitempty"`
	RemoteHost      string `json:"remote_host,omitempty"`
	RemotePort      int    `json:"remote_port,omitempty"`
	LocalPort       int    `json:"local_port,omitempty"`
}

func loadParameters() (Parameters, error) {
	buf := blob.Load()
	if buf == nil {
		return Parameters{}, errors.New("invalid blob")
	}
	params := Parameters{}
	return params, json.Unmarshal(buf, &params)
}

func createSsmRequest(params *Parameters) (*ssm.StartSessionInput, error) {
	req := ssm.StartSessionInput{
		Target: &params.Target,
		Reason: &params.Reason,
	}

	switch params.Operation {
	case "forward":
		req.DocumentName = aws.String(DocumentPortForward)
		req.Parameters = map[string][]string{
			"portNumber":      {strconv.Itoa(params.RemotePort)},
			"localPortNumber": {strconv.Itoa(params.LocalPort)},
		}
	case "forwardToHost":
		req.DocumentName = aws.String(DocumentPortForwardToHost)
		req.Parameters = map[string][]string{
			"host":            {params.RemoteHost},
			"portNumber":      {strconv.Itoa(params.RemotePort)},
			"localPortNumber": {strconv.Itoa(params.LocalPort)},
		}
	case "shell":
		req.DocumentName = aws.String(DocumentShell)
	default:
		return nil, errors.New("unknown operation: " + params.Operation)
	}
	return &req, nil
}

func main() {
	params, err := loadParameters()
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("%#v\n", params)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(params.AccessKeyId, params.SecretAccessKey, params.SessionToken),
		),
	)
	if err != nil {
		log.Fatalln(err)
	}

	ssmCl := ssm.NewFromConfig(cfg)

	if params.Text != "" {
		fmt.Println("#### Embedded Message ####")
		fmt.Println(params.Text)
		fmt.Println("#### Embedded Message ####")
	}

	req, err := createSsmRequest(&params)
	if err != nil {
		log.Fatalln(err)
	}

	resp, err := ssmCl.StartSession(ctx, req)
	if err != nil {
		log.Fatalln(err)
	}

	shutdownCtx, err := session.Start(ctx, session.StartOptions{
		SessionId:  *resp.SessionId,
		StreamUrl:  *resp.StreamUrl,
		TokenValue: *resp.TokenValue,
		TargetId:   params.Target,
	})
	if err != nil {
		log.Fatalln(err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
stop:
	for {
		select {
		case <-shutdownCtx.Done():
			break stop
		case <-sigChan:
			// it should cancel everything
			signal.Stop(sigChan)
			cancel()
		}
	}
	_, err = ssmCl.TerminateSession(ctx, &ssm.TerminateSessionInput{SessionId: resp.SessionId})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error cancelling session %s", err)
		os.Exit(-1)
	}
}
