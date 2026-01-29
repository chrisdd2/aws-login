package session

import (
	"context"

	"github.com/aws/session-manager-plugin/src/datachannel"
	"github.com/aws/session-manager-plugin/src/log"
	"github.com/aws/session-manager-plugin/src/sessionmanagerplugin/session"
	_ "github.com/aws/session-manager-plugin/src/sessionmanagerplugin/session/portsession"
	_ "github.com/aws/session-manager-plugin/src/sessionmanagerplugin/session/shellsession"
	"github.com/chrisdd2/session-manager-plugin/appcontext"
	"github.com/google/uuid"
)

type StartOptions struct {
	SessionId     string
	StreamUrl     string
	TokenValue    string
	TargetId      string
	Region        string
	OperationName string
	Profile       string
	SSMEndpoint   string
}

func Start(ctx context.Context, options StartOptions) (shutdownContext context.Context, err error) {
	sess := session.Session{}
	sess.SessionId = options.SessionId
	sess.StreamUrl = options.StreamUrl
	sess.TokenValue = options.TokenValue
	sess.Endpoint = options.SSMEndpoint
	sess.ClientId = uuid.NewString()
	sess.TargetId = options.TargetId
	sess.Region = options.Region
	sess.DataChannel = &datachannel.DataChannel{}
	log := log.Logger(true, "session-manager-plugin")
	if err := sess.Execute(log); err != nil {
		return nil, err
	}
	appcontext.InitContext(ctx)
	go func() {
		ctx := appcontext.GlobalContext()
		<-ctx.Done()
		sess.TerminateSession(log)
	}()
	return appcontext.GlobalContext(), nil
}
