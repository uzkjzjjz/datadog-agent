// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package clusteragent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DataDog/datadog-agent/pkg/api/security"
	apiv1 "github.com/DataDog/datadog-agent/pkg/clusteragent/api/v1"
	"github.com/DataDog/datadog-agent/pkg/clusteragent/clusterchecks/types"
	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/util/retry"
	"github.com/DataDog/datadog-agent/pkg/version"
)

/*
Client to query the Datadog Cluster Agent (DCA) API.
*/

const (
	authorizationHeaderKey = "Authorization"
	// RealIPHeader refers to the cluster level check runner ip passed in the request headers
	RealIPHeader = "X-Real-Ip"
)

var globalClusterAgentClient *DCAClient

type metadataNames []string

// DCAClientInterface  is required to query the API of Datadog cluster agent
type DCAClientInterface interface {
	Version() version.Version
	ClusterAgentAPIEndpoint() string

	GetVersion() (version.Version, error)
	GetNodeLabels(nodeName string) (map[string]string, error)
	GetNodeAnnotations(nodeName string) (map[string]string, error)
	GetNamespaceLabels(nsName string) (map[string]string, error)
	GetPodsMetadataForNode(nodeName string) (apiv1.NamespacesPodsStringsSet, error)
	GetKubernetesMetadataNames(nodeName, ns, podName string) ([]string, error)
	GetCFAppsMetadataForNode(nodename string) (map[string][]string, error)

	PostClusterCheckStatus(ctx context.Context, nodeName string, status types.NodeStatus) (types.StatusResponse, error)
	GetClusterCheckConfigs(ctx context.Context, nodeName string) (types.ConfigResponse, error)
	GetEndpointsCheckConfigs(ctx context.Context, nodeName string) (types.ConfigResponse, error)
	GetKubernetesClusterID() (string, error)
}

// DCAClient is required to query the API of Datadog cluster agent
type DCAClient struct {
	// used to setup the DCAClient
	initRetry retry.Retrier

	clusterAgentAPIEndpoint       string          // ${SCHEME}://${clusterAgentHost}:${PORT}
	ClusterAgentVersion           version.Version // Version of the cluster-agent we're connected to
	clusterAgentAPIClient         *http.Client
	clusterAgentAPIRequestHeaders http.Header
	leaderClient                  *leaderClient
}

// resetGlobalClusterAgentClient is a helper to remove the current DCAClient global
// It is ONLY to be used for tests
func resetGlobalClusterAgentClient() {
	globalClusterAgentClient = nil
}

// GetClusterAgentClient returns or init the DCAClient
func GetClusterAgentClient() (DCAClientInterface, error) {
	if globalClusterAgentClient == nil {
		globalClusterAgentClient = &DCAClient{}
		globalClusterAgentClient.initRetry.SetupRetrier(&retry.Config{ //nolint:errcheck
			Name:              "clusterAgentClient",
			AttemptMethod:     globalClusterAgentClient.init,
			Strategy:          retry.Backoff,
			InitialRetryDelay: 1 * time.Second,
			MaxRetryDelay:     5 * time.Minute,
		})
	}
	if err := globalClusterAgentClient.initRetry.TriggerRetry(); err != nil {
		log.Debugf("Cluster Agent init error: %v", err)
		return nil, err
	}
	return globalClusterAgentClient, nil
}

var goroutineSpace = []byte("goroutine ")

var littleBuf = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 64)
		return &buf
	},
}

func curGoroutineID() uint64 {
	bp := littleBuf.Get().(*[]byte)
	defer littleBuf.Put(bp)
	b := *bp
	b = b[:runtime.Stack(b, false)]
	// Parse the 4707 out of "goroutine 4707 ["
	b = bytes.TrimPrefix(b, goroutineSpace)
	i := bytes.IndexByte(b, ' ')
	if i < 0 {
		panic(fmt.Sprintf("No space found in %q", b))
	}
	b = b[:i]
	n, err := strconv.ParseUint(string(b), 10, 64)
	if err != nil {
		panic(fmt.Sprintf("Failed to parse goroutine ID out of %q: %v", b, err))
	}
	return n
}

var eventSeq, requestSeq uint64 = 0, 0

func getCustomClientTracer(requestNumber uint64) *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GetConn: func(hostPort string) {
			eventNum := atomic.AddUint64(&eventSeq, 1)
			log.Infof("VBDEBUG | GetConn | %d | %d | %s", eventNum, requestNumber, hostPort)
		},
		GotConn: func(gci httptrace.GotConnInfo) {
			eventNum := atomic.AddUint64(&eventSeq, 1)
			log.Infof("VBDEBUG | GotConn | %d | %d | %+v", eventNum, requestNumber, gci)
		},
		PutIdleConn: func(err error) {
			eventNum := atomic.AddUint64(&eventSeq, 1)
			log.Infof("VBDEBUG | PutIdleConn | %d | %d | err: %v", eventNum, requestNumber, err)
		},
		DNSStart: func(di httptrace.DNSStartInfo) {
			eventNum := atomic.AddUint64(&eventSeq, 1)
			log.Infof("VBDEBUG | DNSStart | %d | %d | host: %s", eventNum, requestNumber, di.Host)
		},
		DNSDone: func(di httptrace.DNSDoneInfo) {
			eventNum := atomic.AddUint64(&eventSeq, 1)
			log.Infof("VBDEBUG | DNSDone | %d | %d | %+v", eventNum, requestNumber, di)
		},
		ConnectStart: func(network, addr string) {
			eventNum := atomic.AddUint64(&eventSeq, 1)
			log.Infof("VBDEBUG | ConnectStart | %d | %d | %s/%s", eventNum, requestNumber, network, addr)
		},
		ConnectDone: func(network, addr string, err error) {
			eventNum := atomic.AddUint64(&eventSeq, 1)
			log.Infof("VBDEBUG | ConnectDone | %d | %d | %s/%s, err: %v", eventNum, requestNumber, network, addr, err)
		},
		TLSHandshakeStart: func() {
			eventNum := atomic.AddUint64(&eventSeq, 1)
			log.Infof("VBDEBUG | TLSHandshakeStart | %d", eventNum)
		},
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			eventNum := atomic.AddUint64(&eventSeq, 1)
			log.Infof("VBDEBUG | TLSHandshakeDone | %d | server: %s, resume: %t, complete: %t", eventNum, requestNumber, cs.ServerName, cs.DidResume, cs.HandshakeComplete)
		},
	}
}

type LoggingRoundTriper struct {
	tr *http.Transport
}

func (lt *LoggingRoundTriper) RoundTrip(req *http.Request) (*http.Response, error) {
	eventNum := atomic.AddUint64(&eventSeq, 1)
	goRoutineID := curGoroutineID()
	log.Infof("VBDEBUG | TRANS | %d | %d | RoundTrip Query: %s, %s", eventNum, goRoutineID, req.Method, req.URL.String())
	resp, err := lt.tr.RoundTrip(req)
	var statusCode int
	if resp != nil {
		statusCode = resp.StatusCode
	}

	eventNum = atomic.AddUint64(&eventSeq, 1)
	log.Infof("VBDEBUG | TRANS | %d | %d | RoundTrip Response: %s, %s, rc: %d, err: %v", eventNum, goRoutineID, req.Method, req.URL.String(), statusCode, err)
	return resp, err
}

func buildDCAHttpClient() *http.Client {
	// Using default Dialer (same as default Transport code)
	dialer := net.Dialer{
		Timeout:   2 * time.Second,
		KeepAlive: 10 * time.Second,
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			goRoutineID := curGoroutineID()
			eventNum := atomic.AddUint64(&eventSeq, 1)
			log.Infof("VBDEBUG | DIAL | %d | %d | Dialing to: %s/%s", eventNum, goRoutineID, network, addr)
			conn, err := dialer.DialContext(ctx, network, addr)

			var conStr string
			var connAddr net.Addr
			if conn != nil {
				connAddr = conn.LocalAddr()
				if connAddr != nil {
					conStr += "local: '" + connAddr.String() + "'"
				}

				connAddr = conn.RemoteAddr()
				if connAddr != nil {
					conStr += " remote: '" + connAddr.String() + "'"
				}
			}

			eventNum = atomic.AddUint64(&eventSeq, 1)
			log.Infof("VBDEBUG | DIAL | %d | %d | Dialing to: %s/%s FINISHED!, conn: %v, connStr: %s, err: %v", eventNum, goRoutineID, network, addr, conn, conStr, err)
			return conn, err
		},
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout: 1 * time.Second,
		MaxConnsPerHost:     1,
		IdleConnTimeout:     5 * time.Minute,
	}

	return &http.Client{
		Transport: &LoggingRoundTriper{tr: tr},
		Timeout:   3 * time.Second,
	}
}

func (c *DCAClient) init() error {
	var err error

	c.clusterAgentAPIEndpoint, err = getClusterAgentEndpoint()
	if err != nil {
		return err
	}

	authToken, err := security.GetClusterAgentAuthToken()
	if err != nil {
		return err
	}

	c.clusterAgentAPIRequestHeaders = http.Header{}
	c.clusterAgentAPIRequestHeaders.Set(authorizationHeaderKey, fmt.Sprintf("Bearer %s", authToken))
	podIP := config.Datadog.GetString("clc_runner_host")
	c.clusterAgentAPIRequestHeaders.Set(RealIPHeader, podIP)

	// TODO remove insecure
	c.clusterAgentAPIClient = buildDCAHttpClient()

	// Validate the cluster-agent client by checking the version
	c.ClusterAgentVersion, err = c.GetVersion()
	if err != nil {
		return err
	}
	log.Infof("Successfully connected to the Datadog Cluster Agent %s", c.ClusterAgentVersion.String())

	// Clone the http client in a new client with built-in redirect handler
	c.leaderClient = newLeaderClient(c.clusterAgentAPIClient, c.clusterAgentAPIEndpoint)

	return nil
}

// Version returns ClusterAgentVersion already stored in the DCAClient
func (c *DCAClient) Version() version.Version {
	return c.ClusterAgentVersion
}

// ClusterAgentAPIEndpoint returns the Agent API Endpoint URL as a string
func (c *DCAClient) ClusterAgentAPIEndpoint() string {
	return c.clusterAgentAPIEndpoint
}

// getClusterAgentEndpoint provides a validated https endpoint from configuration keys in datadog.yaml:
// 1st. configuration key "cluster_agent.url" (or the DD_CLUSTER_AGENT_URL environment variable),
//      add the https prefix if the scheme isn't specified
// 2nd. environment variables associated with "cluster_agent.kubernetes_service_name"
//      ${dcaServiceName}_SERVICE_HOST and ${dcaServiceName}_SERVICE_PORT
func getClusterAgentEndpoint() (string, error) {
	const configDcaURL = "cluster_agent.url"
	const configDcaSvcName = "cluster_agent.kubernetes_service_name"

	dcaURL := config.Datadog.GetString(configDcaURL)
	if dcaURL != "" {
		if strings.HasPrefix(dcaURL, "http://") {
			return "", fmt.Errorf("cannot get cluster agent endpoint, not a https scheme: %s", dcaURL)
		}
		if strings.Contains(dcaURL, "://") == false {
			log.Tracef("Adding https scheme to %s: https://%s", dcaURL, dcaURL)
			dcaURL = fmt.Sprintf("https://%s", dcaURL)
		}
		u, err := url.Parse(dcaURL)
		if err != nil {
			return "", err
		}
		if u.Scheme != "https" {
			return "", fmt.Errorf("cannot get cluster agent endpoint, not a https scheme: %s", u.Scheme)
		}
		log.Debugf("Connecting to the configured URL for the Datadog Cluster Agent: %s", dcaURL)
		return u.String(), nil
	}

	// Construct the URL with the Kubernetes service environment variables
	// *_SERVICE_HOST and *_SERVICE_PORT
	dcaSvc := config.Datadog.GetString(configDcaSvcName)
	log.Debugf("Identified service for the Datadog Cluster Agent: %s", dcaSvc)
	if dcaSvc == "" {
		return "", fmt.Errorf("cannot get a cluster agent endpoint, both %s and %s are empty", configDcaURL, configDcaSvcName)
	}

	dcaSvc = strings.ToUpper(dcaSvc)
	dcaSvc = strings.Replace(dcaSvc, "-", "_", -1) // Kubernetes replaces "-" with "_" in the service names injected in the env var.

	// host
	dcaSvcHostEnv := fmt.Sprintf("%s_SERVICE_HOST", dcaSvc)
	dcaSvcHost := os.Getenv(dcaSvcHostEnv)
	if dcaSvcHost == "" {
		return "", fmt.Errorf("cannot get a cluster agent endpoint for kubernetes service %s, env %s is empty", dcaSvc, dcaSvcHostEnv)
	}

	// port
	dcaSvcPort := os.Getenv(fmt.Sprintf("%s_SERVICE_PORT", dcaSvc))
	if dcaSvcPort == "" {
		return "", fmt.Errorf("cannot get a cluster agent endpoint for kubernetes service %s, env %s is empty", dcaSvc, dcaSvcPort)
	}

	// validate the URL
	dcaURL = fmt.Sprintf("https://%s:%s", dcaSvcHost, dcaSvcPort)
	u, err := url.Parse(dcaURL)
	if err != nil {
		return "", err
	}

	return u.String(), nil
}

// GetVersion fetches the version of the Cluster Agent. Used in the agent status command.
func (c *DCAClient) GetVersion() (version.Version, error) {
	const dcaVersionPath = "version"
	var version version.Version
	var err error

	// https://host:port/version
	rawURL := fmt.Sprintf("%s/%s", c.clusterAgentAPIEndpoint, dcaVersionPath)

	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), getCustomClientTracer(atomic.AddUint64(&requestSeq, 1))), "GET", rawURL, nil)
	if err != nil {
		return version, err
	}
	req.Header = c.clusterAgentAPIRequestHeaders

	resp, err := c.clusterAgentAPIClient.Do(req)
	if err != nil {
		return version, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return version, fmt.Errorf("unexpected status code from cluster agent: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return version, err
	}

	err = json.Unmarshal(body, &version)

	return version, err
}

// GetNodeLabels returns the node labels from the Cluster Agent.
func (c *DCAClient) getMapStringString(queryPath, objectName string) (map[string]string, error) {
	var err error
	var result map[string]string

	// https://host:port/api/v1/tags/node/{nodeName}
	// https://host:port/api/v1/tags/namespace/{nsName}
	// https://host:port/api/v1/annotations/node/{nodeName}
	rawURL := fmt.Sprintf("%s/%s/%s", c.clusterAgentAPIEndpoint, queryPath, objectName)

	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), getCustomClientTracer(atomic.AddUint64(&requestSeq, 1))), "GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header = c.clusterAgentAPIRequestHeaders

	resp, err := c.clusterAgentAPIClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code from cluster agent: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(body, &result)
	return result, err
}

// GetNodeLabels returns the node labels from the Cluster Agent.
func (c *DCAClient) GetNodeLabels(nodeName string) (map[string]string, error) {
	return c.getMapStringString("api/v1/tags/node", nodeName)
}

// GetNamespaceLabels returns the namespace labels from the Cluster Agent.
func (c *DCAClient) GetNamespaceLabels(nsName string) (map[string]string, error) {
	return c.getMapStringString("api/v1/tags/namespace", nsName)
}

// GetNodeAnnotations returns the node annotations from the Cluster Agent.
func (c *DCAClient) GetNodeAnnotations(nodeName string) (map[string]string, error) {
	return c.getMapStringString("api/v1/annotations/node", nodeName)
}

// GetCFAppsMetadataForNode returns the CF application tags from the Cluster Agent.
func (c *DCAClient) GetCFAppsMetadataForNode(nodename string) (map[string][]string, error) {
	const dcaCFAppsMeta = "api/v1/tags/cf/apps"
	var err error
	var tags map[string][]string

	// https://host:port/api/v1/tags/cf/apps/{nodename}
	rawURL := fmt.Sprintf("%s/%s/%s", c.clusterAgentAPIEndpoint, dcaCFAppsMeta, nodename)

	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), getCustomClientTracer(atomic.AddUint64(&requestSeq, 1))), "GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header = c.clusterAgentAPIRequestHeaders

	resp, err := c.clusterAgentAPIClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code from cluster agent: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(body, &tags)
	return tags, err
}

// GetPodsMetadataForNode queries the datadog cluster agent to get nodeName registered
// Kubernetes pods metadata.
func (c *DCAClient) GetPodsMetadataForNode(nodeName string) (apiv1.NamespacesPodsStringsSet, error) {
	const dcaMetadataPath = "api/v1/tags/pod"
	var err error

	if c == nil {
		return nil, fmt.Errorf("cluster agent's client is not properly initialized")
	}
	/* https://host:port/api/v1/tags/pod/{nodeName}
	response example:
	{
		"Nodes": {
			"node1": {
				"services": {
					"default": {
						"datadog-monitoring-cluster-agent-58f45b9b44-pkxrv": {
							"datadog-monitoring-cluster-agent": {},
							"datadog-monitoring-cluster-agent-metrics-api": {}
						}
					},
					"kube-system": {
						"kube-dns-6b98c9c9bf-ts7gc": {
							"kube-dns": {}
						}
					}
				}
			}
		}
	}
	*/
	rawURL := fmt.Sprintf("%s/%s/%s", c.clusterAgentAPIEndpoint, dcaMetadataPath, nodeName)
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), getCustomClientTracer(atomic.AddUint64(&requestSeq, 1))), "GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header = c.clusterAgentAPIRequestHeaders

	resp, err := c.clusterAgentAPIClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code from cluster agent: %d", resp.StatusCode)
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	metadataPodPayload := apiv1.NewMetadataResponse()
	if err = json.Unmarshal(b, metadataPodPayload); err != nil {
		return nil, err
	}

	if _, ok := metadataPodPayload.Nodes[nodeName]; !ok {
		return nil, fmt.Errorf("cluster agent didn't return pods metadata for node: %s", nodeName)
	}
	return metadataPodPayload.Nodes[nodeName].Services, nil
}

// GetKubernetesMetadataNames queries the datadog cluster agent to get nodeName/podName registered
// Kubernetes metadata.
func (c *DCAClient) GetKubernetesMetadataNames(nodeName, ns, podName string) ([]string, error) {
	const dcaMetadataPath = "api/v1/tags/pod"
	var metadataNames metadataNames
	var err error

	if c == nil {
		return nil, fmt.Errorf("cluster agent's client is not properly initialized")
	}
	if ns == "" {
		return nil, fmt.Errorf("namespace is empty")
	}

	// https://host:port/api/v1/metadata/{nodeName}/{ns}/{pod-[0-9a-z]+}
	rawURL := fmt.Sprintf("%s/%s/%s/%s/%s", c.clusterAgentAPIEndpoint, dcaMetadataPath, nodeName, ns, podName)
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), getCustomClientTracer(atomic.AddUint64(&requestSeq, 1))), "GET", rawURL, nil)
	if err != nil {
		return metadataNames, err
	}
	req.Header = c.clusterAgentAPIRequestHeaders

	resp, err := c.clusterAgentAPIClient.Do(req)
	if err != nil {
		return metadataNames, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return metadataNames, fmt.Errorf("unexpected status code from cluster agent: %d", resp.StatusCode)
	}

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return metadataNames, err
	}
	err = json.Unmarshal(b, &metadataNames)
	if err != nil {
		return metadataNames, err
	}

	return metadataNames, nil
}

// GetKubernetesClusterID queries the datadog cluster agent to get the Kubernetes cluster ID
// Prefer calling clustername.GetClusterID which has a cached response
func (c *DCAClient) GetKubernetesClusterID() (string, error) {
	const dcaClusterIDPath = "api/v1/cluster/id"
	var clusterID string
	var err error

	if c == nil {
		return "", fmt.Errorf("cluster agent's client is not properly initialized")
	}

	// https://host:port/api/v1/cluster/id
	rawURL := fmt.Sprintf("%s/%s", c.clusterAgentAPIEndpoint, dcaClusterIDPath)
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), getCustomClientTracer(atomic.AddUint64(&requestSeq, 1))), "GET", rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header = c.clusterAgentAPIRequestHeaders

	resp, err := c.clusterAgentAPIClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code from cluster agent: %d", resp.StatusCode)
	}

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(b, &clusterID)
	return clusterID, err
}
