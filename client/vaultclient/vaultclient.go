package vaultclient

import (
	"container/heap"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/nomad/nomad/structs/config"
	vaultapi "github.com/hashicorp/vault/api"
	vaultduration "github.com/hashicorp/vault/helper/duration"
)

type VaultClient interface {
	Start()
	Stop()
	DeriveToken() (string, error)
	GetConsulACL() (string, error)
	RenewToken(string) <-chan error
	StopRenewToken(string) error
	RenewLease(string) <-chan error
	StopRenewLease(string) error
}

type vaultClient struct {
	running        bool
	token          string
	taskTokenTTL   string
	vaultAPIClient *vaultapi.Client
	updateCh       chan struct{}
	stopCh         chan struct{}
	heap           *vaultClientHeap
	lock           sync.RWMutex
	logger         *log.Logger
}

type vaultClientRenewalRequest struct {
	errCh chan error
	id    string
}

type vaultClientHeapEntry struct {
	data  *vaultClientRenewalRequest
	next  time.Time
	index int
}

type vaultClientHeap struct {
	heapMap map[string]*vaultClientHeapEntry
	heap    vaultDataHeapImp
}

func (h *vaultClientHeap) IsTracked(id string) bool {
	_, ok := h.heapMap[id]
	return ok
}

func (h *vaultClientHeap) Length() int {
	return len(h.heap)
}

func (h *vaultClientHeap) Peek() *vaultClientHeapEntry {
	if len(h.heap) == 0 {
		return nil
	}

	return h.heap[0]
}

func (h *vaultClientHeap) Push(vData *vaultClientRenewalRequest, next time.Time) error {
	if _, ok := h.heapMap[vData.id]; ok {
		return fmt.Errorf("entry %v already exists", vData.id)
	}

	heapEntry := &vaultClientHeapEntry{
		data: vData,
		next: next,
	}
	h.heapMap[vData.id] = heapEntry
	heap.Push(&h.heap, heapEntry)
	return nil
}

func (h *vaultClientHeap) Update(vData *vaultClientRenewalRequest, next time.Time) error {
	if entry, ok := h.heapMap[vData.id]; ok {
		entry.data = vData
		entry.next = next
		heap.Fix(&h.heap, entry.index)
		return nil
	}

	return fmt.Errorf("heap doesn't contain %v", vData.id)
}

type vaultDataHeapImp []*vaultClientHeapEntry

func NewVaultClient(vaultConfig *config.VaultConfig, logger *log.Logger) (*vaultClient, error) {
	if vaultConfig == nil {
		return nil, fmt.Errorf("nil, vaultConfig")
	}
	if vaultConfig.Token == "" {
		return nil, fmt.Errorf("periodic_token not set")
	}

	log.Printf("vaultConfig.TaskTokenTTL: %s\n", vaultConfig.TaskTokenTTL)

	return &vaultClient{
		token:        vaultConfig.Token,
		taskTokenTTL: vaultConfig.TaskTokenTTL,
		stopCh:       make(chan struct{}),
		updateCh:     make(chan struct{}, 1),
		heap:         NewVaultDataHeap(),
		logger:       logger,
	}, nil
}

func NewVaultDataHeap() *vaultClientHeap {
	return &vaultClientHeap{
		heapMap: make(map[string]*vaultClientHeapEntry),
		heap:    make(vaultDataHeapImp, 0),
	}
}

func (c *vaultClient) Start() {
	c.logger.Printf("[INFO] vaultClient started")
	c.lock.Lock()
	c.running = true
	c.lock.Unlock()
	go c.run()
}

func (c *vaultClient) run() {
	var renewalCh <-chan time.Time
	for {
		renewalReq, renewalTime := c.nextRenewal()
		if renewalTime.IsZero() {
			renewalCh = nil
		} else {
			renewalDuration := renewalTime.Sub(time.Now())
			renewalCh = time.After(renewalDuration)
			c.logger.Printf("[INFO] setting renewal to %s\n", renewalDuration)
		}

		select {
		case <-renewalCh:
			if err := c.renew(renewalReq); err != nil {
				renewalReq.errCh <- err
			}
		case <-c.updateCh:
			continue
		case <-c.stopCh:
			c.logger.Printf("[INFO] vaultClient stopped")
			return
		}
	}
}

func (c *vaultClient) Stop() {
	close(c.stopCh)
}

func (c *vaultClient) DeriveToken() (string, error) {
	tcr := &vaultapi.TokenCreateRequest{
		Policies:    []string{"foo", "bar"},
		TTL:         "10s",
		DisplayName: "derived-for-task",
		Renewable:   new(bool),
	}
	*tcr.Renewable = true

	client, err := c.getVaultAPIClient()
	if err != nil {
		return "", fmt.Errorf("failed to create vault API client: %v", err)
	}

	wrapLookupFunc := func(method, path string) string {
		if method == "POST" && path == "auth/token/create" {
			return "60s"
		}
		return ""
	}
	client.SetWrappingLookupFunc(wrapLookupFunc)

	secret, err := client.Auth().Token().Create(tcr)
	if err != nil {
		return "", fmt.Errorf("failed to create vault token: %v", err)
	}
	if secret == nil || secret.WrapInfo == nil || secret.WrapInfo.Token == "" ||
		secret.WrapInfo.WrappedAccessor == "" {
		return "", fmt.Errorf("failed to derive a wrapped vault token")
	}

	wrappedToken := secret.WrapInfo.Token

	unwrapResp, err := client.Logical().Unwrap(wrappedToken)
	if err != nil {
		return "", fmt.Errorf("failed to unwrap the token: %v", err)
	}
	if unwrapResp == nil || unwrapResp.Auth == nil || unwrapResp.Auth.ClientToken == "" {
		return "", fmt.Errorf("failed to unwrap the token")
	}

	return unwrapResp.Auth.ClientToken, nil
}

func (c *vaultClient) GetConsulACL() (string, error) {
	return "", nil
}

func (c *vaultClient) RenewToken(token string) <-chan error {
	renewalReq := &vaultClientRenewalRequest{
		errCh: make(chan error),
		id:    token,
	}

	if err := c.renew(renewalReq); err != nil {
		renewalReq.errCh <- err
	}

	// Signal an update.
	if c.running {
		select {
		case c.updateCh <- struct{}{}:
		default:
		}
	}

	return renewalReq.errCh
}

func (c *vaultClient) renew(req *vaultClientRenewalRequest) error {
	c.logger.Printf("[INFO] renew called for id: %s", req.id)
	if req == nil {
		return fmt.Errorf("nil renewal request")
	}
	if req.id == "" {
		return fmt.Errorf("missing id in renewal request")
	}

	client, err := c.getVaultAPIClient()
	if err != nil {
		return fmt.Errorf("failed to create vault API client: %v", err)
	}

	increment, err := vaultduration.ParseDurationSecond(c.taskTokenTTL)
	if err != nil {
		return fmt.Errorf("failed to parse task_token_ttl:%v", err)
	}
	// Convert increment to seconds
	increment /= time.Second

	renewResp, err := client.Auth().Token().Renew(req.id, int(increment))
	if err != nil {
		return fmt.Errorf("failed to renew the vault token: %v", err)
	}
	if renewResp == nil || renewResp.Auth == nil {
		return fmt.Errorf("failed to renew the vault token")
	}

	leaseDuration, err := vaultduration.ParseDurationSecond(strconv.Itoa(renewResp.Auth.LeaseDuration))
	if err != nil {
		return fmt.Errorf("failed to parse the leaseduration:%v", err)
	}

	next := time.Now().Add(leaseDuration / 2)
	if c.heap.IsTracked(req.id) {
		if err := c.heap.Update(req, next); err != nil {
			return fmt.Errorf("failed to update heap entry. err: %v", err)
		}
	} else {
		if err := c.heap.Push(req, next); err != nil {
			return fmt.Errorf("failed to push an entry to heap.  err: %v", err)
		}
	}

	return nil
}

func (c *vaultClient) nextRenewal() (*vaultClientRenewalRequest, time.Time) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	if c.heap.Length() == 0 {
		return nil, time.Time{}
	}

	nextEntry := c.heap.Peek()
	if nextEntry == nil {
		return nil, time.Time{}
	}

	return nextEntry.data, nextEntry.next
}

func (c *vaultClient) getVaultAPIClient() (*vaultapi.Client, error) {
	if c.vaultAPIClient == nil {
		// Get the default configuration
		config := vaultapi.DefaultConfig()

		// Read the environment variables and update the configuration
		if err := config.ReadEnvironment(); err != nil {
			return nil, fmt.Errorf("failed to read the environment: %v", err)
		}

		// Create a Vault API Client
		client, err := vaultapi.NewClient(config)
		if err != nil {
			return nil, fmt.Errorf("failed to create Vault client: %v", err)
		}

		// Set the authentication required
		client.SetToken(c.token)
		c.vaultAPIClient = client
	}

	return c.vaultAPIClient, nil
}

func (c *vaultClient) StopRenewToken(string) error {
	return nil
}

func (c *vaultClient) RenewLease(string) <-chan error {
	var errCh chan error
	return errCh
}

func (c *vaultClient) StopRenewLease(string) error {
	return nil
}

// The heap interface requires the following methods to be implemented.
// * Push(x interface{}) // add x as element Len()
// * Pop() interface{}   // remove and return element Len() - 1.
// * sort.Interface
//
// sort.Interface comprises of the following methods:
// * Len() int
// * Less(i, j int) bool
// * Swap(i, j int)

func (h vaultDataHeapImp) Len() int { return len(h) }

func (h vaultDataHeapImp) Less(i, j int) bool {
	// Two zero times should return false.
	// Otherwise, zero is "greater" than any other time.
	// (To sort it at the end of the list.)
	// Sort such that zero times are at the end of the list.
	iZero, jZero := h[i].next.IsZero(), h[j].next.IsZero()
	if iZero && jZero {
		return false
	} else if iZero {
		return false
	} else if jZero {
		return true
	}

	return h[i].next.Before(h[j].next)
}

func (h vaultDataHeapImp) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *vaultDataHeapImp) Push(x interface{}) {
	n := len(*h)
	data := x.(*vaultClientHeapEntry)
	data.index = n
	*h = append(*h, data)
}

func (h *vaultDataHeapImp) Pop() interface{} {
	old := *h
	n := len(old)
	data := old[n-1]
	data.index = -1 // for safety
	*h = old[0 : n-1]
	return data
}
