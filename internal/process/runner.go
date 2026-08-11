package process

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

type Output struct {
	Stdout, Stderr                   []byte
	StdoutTruncated, StderrTruncated bool
}
type Runner struct{ MaxStdout, MaxStderr int64 }

type boundedBuffer struct {
	b         bytes.Buffer
	limit     int64
	truncated bool
}

func (w *boundedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := w.limit - int64(w.b.Len())
	if remaining > 0 {
		keep := int64(len(p))
		if keep > remaining {
			keep = remaining
		}
		_, _ = w.b.Write(p[:keep])
	}
	if int64(n) > remaining {
		w.truncated = true
	}
	return n, nil
}

func (r Runner) Run(ctx context.Context, binary string, args ...string) (Output, error) {
	return r.RunInDir(ctx, "", binary, args...)
}
func (r Runner) RunInDir(ctx context.Context, dir, binary string, args ...string) (Output, error) {
	if binary == "" || strings.ContainsAny(binary, "\r\n") {
		return Output{}, errors.New("invalid executable")
	}
	path, err := exec.LookPath(binary)
	if err != nil {
		return Output{}, err
	}
	for _, arg := range args {
		if strings.ContainsAny(arg, "\x00\r\n") {
			return Output{}, errors.New("invalid process argument")
		}
	}
	out := &boundedBuffer{limit: r.MaxStdout}
	errout := &boundedBuffer{limit: r.MaxStderr}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdout = out
	cmd.Stderr = errout
	cmd.Stdin = nil
	cmd.Dir = dir
	cmd.Env = minimalEnvironment()
	err = cmd.Run()
	return Output{Stdout: out.b.Bytes(), Stderr: errout.b.Bytes(), StdoutTruncated: out.truncated, StderrTruncated: errout.truncated}, err
}

func minimalEnvironment() []string {
	path := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	if runtime.GOOS == "windows" {
		path = os.Getenv("SystemRoot") + `\System32;` + os.Getenv("SystemRoot")
	}
	env := []string{"PATH=" + path, "LANG=C", "LC_ALL=C"}
	if root := os.Getenv("SystemRoot"); runtime.GOOS == "windows" && root != "" {
		env = append(env, "SystemRoot="+root)
	}
	return env
}
