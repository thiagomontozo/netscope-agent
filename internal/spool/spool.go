package spool

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Sender interface {
	Send(context.Context, string, json.RawMessage) error
}
type item struct {
	Kind    string          `json:"kind"`
	Payload json.RawMessage `json:"payload"`
}
type Queue struct {
	Dir      string
	MaxBytes int64
	MaxAge   time.Duration
}

func (q Queue) Enqueue(kind string, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b, err := json.Marshal(item{Kind: kind, Payload: payload})
	if err != nil {
		return err
	}
	if int64(len(b)) > q.MaxBytes {
		return errors.New("spool item exceeds total spool limit")
	}
	size, err := q.size()
	if err != nil {
		return err
	}
	if size+int64(len(b)) > q.MaxBytes {
		return errors.New("spool is full")
	}
	safe := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, kind)
	f, err := os.CreateTemp(q.Dir, time.Now().UTC().Format("20060102T150405.000000000")+"-"+safe+"-*.json")
	if err != nil {
		return err
	}
	name := f.Name()
	defer func() { _ = f.Close() }()
	if err = f.Chmod(0o600); err != nil {
		os.Remove(name)
		return err
	}
	if _, err = f.Write(b); err != nil {
		os.Remove(name)
		return err
	}
	return f.Sync()
}
func (q Queue) Flush(ctx context.Context, s Sender) error {
	entries, err := os.ReadDir(q.Dir)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		p := filepath.Join(q.Dir, e.Name())
		info, err := e.Info()
		if err != nil {
			continue
		}
		if time.Since(info.ModTime()) > q.MaxAge {
			_ = os.Remove(p)
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var queued item
		if json.Unmarshal(b, &queued) != nil || queued.Kind == "" {
			_ = os.Remove(p)
			continue
		}
		if err = s.Send(ctx, queued.Kind, queued.Payload); err != nil {
			return err
		}
		if err = os.Remove(p); err != nil {
			return err
		}
	}
	return nil
}
func (q Queue) Health() (int, int64, error) {
	e, err := os.ReadDir(q.Dir)
	if err != nil {
		return 0, 0, err
	}
	var n int
	var size int64
	for _, x := range e {
		if x.IsDir() {
			continue
		}
		i, err := x.Info()
		if err == nil {
			n++
			size += i.Size()
		}
	}
	return n, size, nil
}
func (q Queue) size() (int64, error) { _, n, e := q.Health(); return n, e }
