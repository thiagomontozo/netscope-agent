package modules

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/thiagomontozo/netscope-agent/internal/jobs"
)

func DecodeParameters(data json.RawMessage, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("multiple parameter values are not allowed")
	}
	return nil
}

type Descriptor struct {
	ID, Version                      string
	RiskClass                        jobs.RiskClass
	Implementation                   string
	RequiredTool, RequiredCapability string
	Platforms                        []string
	ConcurrencyLimit                 int
}
type Module interface {
	Descriptor() Descriptor
	Validate(jobs.Envelope) error
	Execute(context.Context, jobs.Envelope) (jobs.ModuleResult, error)
}

type Registry struct {
	modules map[string]Module
	limits  map[string]chan struct{}
	mu      sync.RWMutex
}

func NewRegistry(ms ...Module) (*Registry, error) {
	r := &Registry{modules: map[string]Module{}, limits: map[string]chan struct{}{}}
	for _, m := range ms {
		d := m.Descriptor()
		if d.ID == "" {
			return nil, errors.New("module ID empty")
		}
		if _, ok := r.modules[d.ID]; ok {
			return nil, fmt.Errorf("duplicate module %s", d.ID)
		}
		r.modules[d.ID] = m
		n := d.ConcurrencyLimit
		if n < 1 {
			n = 1
		}
		r.limits[d.ID] = make(chan struct{}, n)
	}
	return r, nil
}
func (r *Registry) Get(id string) (Module, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.modules[id]
	return m, ok
}
func (r *Registry) Descriptors() []Descriptor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Descriptor, 0, len(r.modules))
	for _, m := range r.modules {
		out = append(out, m.Descriptor())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
func (r *Registry) Acquire(ctx context.Context, id string) (func(), error) {
	r.mu.RLock()
	sem, ok := r.limits[id]
	r.mu.RUnlock()
	if !ok {
		return nil, errors.New("unknown module")
	}
	select {
	case sem <- struct{}{}:
		return func() { <-sem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
