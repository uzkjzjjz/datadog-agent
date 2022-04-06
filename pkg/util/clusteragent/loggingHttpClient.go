package clusteragent

import (
	"net/http"
	"runtime/debug"
	"sync/atomic"

	"github.com/DataDog/datadog-agent/pkg/util/log"
)

type loggingClient struct {
	bareClient *http.Client
}

func newLoggingClient(bareClient *http.Client) *loggingClient {
	return &loggingClient{
		bareClient: bareClient,
	}
}

var logID uint32

func (client *loggingClient) Do(req *http.Request) (*http.Response, error) {
	id := atomic.AddUint32(&logID, 1)
	log.Infof("XXXXX vvvvv %6d DCAClient.Do(req=%#v)", id, req)
	log.Infof("XXXXX stack: %s", debug.Stack())
	res, err := client.bareClient.Do(req)
	log.Infof("XXXXX ^^^^^ %6d DCAClient.Do(req) (response=%#v, error=#%v)", id, res, err)
	return res, err
}

func (client *loggingClient) SetCheckRedirect(f func(req *http.Request, via []*http.Request) error) {
	client.bareClient.CheckRedirect = f
}
