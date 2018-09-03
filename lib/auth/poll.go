package auth

import (
	"context"
	"crypto/x509"
	"sync"
	"time"

	"github.com/gravitational/teleport/lib/defaults"

	"github.com/gravitational/trace"
)

// CertPoolGetter returns cert pool
type CertPoolGetter func() (*x509.CertPool, error)

type PollerConfig struct {
	Period  time.Duration
	Getter  CertPoolGetter
	Context context.Context
}

func (p *PollerConfig) CheckAndSetDefaults() error {
	if p.Getter == nil {
		return trace.BadParameter("missing parameter Getter")
	}
	if p.Context == nil {
		p.Context = context.Background()
	}
	if p.Period == 0 {
		p.Period = defaults.HighResPollingPeriod
	}
	return nil
}

func NewPoller(cfg PollerConfig) (*Poller, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	// to make sure that in most cases
	// poller will return a meaningful value on the first
	// start
	pool, err := cfg.Getter()
	ctx, cancel := context.WithCancel(cfg.Context)
	poller := &Poller{
		PollerConfig: cfg,
		RWMutex:      &sync.RWMutex{},
		cancel:       cancel,
		ctx:          ctx,
		lastCertPool: pool,
		lastErr:      err,
	}
	go poller.poll()
	return poller, nil
}

// Poller is responsible for getting
type Poller struct {
	PollerConfig
	lastCertPool *x509.CertPool
	lastErr      error
	*sync.RWMutex
	cancel context.CancelFunc
	ctx    context.Context
}

// CertPool
func (p *Poller) CertPool() (*x509.CertPool, error) {
	p.RLock()
	defer p.RUnlock()
	if p.lastErr != nil {
		return nil, p.lastErr
	}
	return p.lastCertPool, nil
}

func (p *Poller) setLastValues(pool *x509.CertPool, err error) {
	p.Lock()
	defer p.Unlock()
	log.Debugf("Poller set values %v %v.", p.lastCertPool, p.lastErr)
	p.lastErr = err
	p.lastCertPool = pool
}

func (p *Poller) Close() error {
	p.cancel()
	return nil
}

func (p *Poller) poll() {
	ticker := time.NewTicker(p.Period)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.setLastValues(p.Getter())
		}
	}
}
