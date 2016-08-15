package vaultclient

import (
	"container/heap"
	"encoding/json"
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
	periodicToken  string
	vaultAPIClient *vaultapi.Client
	stopCh         chan struct{}
	heap           *vaultClientHeap
	lock           sync.RWMutex
}

type vaultClientRenewalData struct {
	errCh chan error
	id    string
}

type vaultClientHeapEntry struct {
	data  *vaultClientRenewalData
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

func (h *vaultClientHeap) Push(vData *vaultClientRenewalData, next time.Time) error {
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

func (h *vaultClientHeap) Update(vData *vaultClientRenewalData, next time.Time) error {
	if entry, ok := h.heapMap[vData.id]; ok {
		entry.data = vData
		entry.next = next
		heap.Fix(&h.heap, entry.index)
		return nil
	}

	return fmt.Errorf("heap doesn't contain %v", vData.id)
}

type vaultDataHeapImp []*vaultClientHeapEntry

func NewVaultClient(vaultConfig *config.VaultConfig) (*vaultClient, error) {
	if vaultConfig == nil {
		return nil, fmt.Errorf("nil, vaultConfig")
	}
	if vaultConfig.PeriodicToken == "" {
		return nil, fmt.Errorf("periodic_token not set")
	}

	return &vaultClient{
		periodicToken: vaultConfig.PeriodicToken,
		stopCh:        make(chan struct{}),
		heap:          NewVaultDataHeap(),
	}, nil
}

func NewVaultDataHeap() *vaultClientHeap {
	return &vaultClientHeap{
		heapMap: make(map[string]*vaultClientHeapEntry),
		heap:    make(vaultDataHeapImp, 0),
	}
}

func (c *vaultClient) Start() {
	log.Printf("vaultclient: Started========================***=================================")
	c.lock.Lock()
	c.running = true
	c.lock.Unlock()

	// TODO: Test code begins
	derivedWrappedToken, err := c.DeriveToken()
	if err != nil {
		log.Printf("vaultclient: failed to derive a vault token: %v", err)
	}
	c.RenewToken(derivedWrappedToken)
	// TODO: Test code ends

	go c.run()
}

func (c *vaultClient) run() {
	var renewalCh <-chan time.Time
	for {
		renewalData, renewalTime := c.nextRenewal()
		if renewalTime.IsZero() {
			renewalCh = nil
		} else {
			renewalDuration := renewalTime.Sub(time.Now())
			renewalCh = time.After(renewalDuration)
		}

		select {
		case <-renewalCh:
			log.Printf("renewal time for data: %#v\n", renewalData)
			next := time.Now().Add(5 * time.Second)
			if err := c.heap.Update(renewalData, next); err != nil {
				log.Printf("vaultclient: error while resetting renewal time: %v\n", err)
				renewalData.errCh <- fmt.Errorf("failed to update heap entry: %v", err)
			}
		case <-c.stopCh:
			log.Printf("vaultclient: Stopped=======================***==================================")
			return
		}
	}
}

func (c *vaultClient) Stop() {
	close(c.stopCh)
}

func (c *vaultClient) DeriveToken() (string, error) {
	tcr := &vaultapi.TokenCreateRequest{
		ID:          "vault-token-123",
		Policies:    []string{"foo", "bar"},
		TTL:         "10s",
		DisplayName: "derived-token",
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
	errCh := make(chan error)
	client, err := c.getVaultAPIClient()
	if err != nil {
		errCh <- fmt.Errorf("failed to create vault API client: %v", err)
		return errCh
	}

	lookupResp, err := client.Auth().Token().Lookup(token)
	if err != nil {
		errCh <- fmt.Errorf("failed to lookup the vault token: %v", err)
		return errCh
	}
	if lookupResp == nil || lookupResp.Data == nil {
		errCh <- fmt.Errorf("failed to lookup the vault token: %v", err)
		return errCh
	}

	creationTTL := lookupResp.Data["creation_ttl"].(json.Number)
	increment, err := creationTTL.Int64()
	if err != nil {
		errCh <- fmt.Errorf("failed to fetch increment: %v", err)
		return errCh
	}

	renewResp, err := client.Auth().Token().Renew(token, int(increment))
	if err != nil {
		errCh <- fmt.Errorf("failed to renew the vault token: %v", err)
		return errCh
	}
	if renewResp == nil || renewResp.Auth == nil {
		errCh <- fmt.Errorf("failed to renew the vault token")
		return errCh
	}

	leaseDuration, err := vaultduration.ParseDurationSecond(strconv.Itoa(renewResp.Auth.LeaseDuration))
	if err != nil {
		errCh <- fmt.Errorf("failed to parse the leaseduration:%v", err)
		return errCh
	}

	// Add or update the token in the heap
	// Check if the token is already present in the heap
	renewalData := &vaultClientRenewalData{
		errCh: errCh,
		id:    token,
	}

	log.Printf("vaultclient: RenewToken(): leaseDuration: %s\n", leaseDuration)

	next := time.Now().Add(leaseDuration / 2)
	if c.heap.IsTracked(token) {
		if err := c.heap.Update(renewalData, next); err != nil {
			errCh <- fmt.Errorf("failed to update heap entry. err: %v", err)
			return errCh
		}
	} else {
		if err := c.heap.Push(renewalData, next); err != nil {
			errCh <- fmt.Errorf("failed to push an entry to heap.  err: %v", err)
			return errCh
		}
	}

	// TODO: Test code begins
	renewalData2 := &vaultClientRenewalData{
		errCh: make(chan error),
		id:    token + "4",
	}
	if err := c.heap.Push(renewalData2, next.Add(10*time.Second)); err != nil {
		log.Printf("failed to push renewalData: err: %v.  vaultTokenData %#v\n", err, renewalData)
	}
	// TODO: Test code ends

	log.Printf("vaultclient: heap len: %d", c.heap.Length())
	log.Printf("vaultclient: heap peek: %#v", c.heap.Peek())

	return errCh
}

func (c *vaultClient) nextRenewal() (*vaultClientRenewalData, time.Time) {
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
		client.SetToken(c.periodicToken)
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
