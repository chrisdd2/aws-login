package appcontext

import (
	"context"
	"sync"
)

var ctx context.Context
var cancel context.CancelFunc
var lock sync.Mutex

func InitContext(ctx context.Context) {
	lock.Lock()
	ctx, cancel = context.WithCancel(context.Background())
	lock.Unlock()
}

func GlobalContext() context.Context {
	return ctx
}

func Shutdown() {
	if cancel != nil {
		cancel()
	}
}
