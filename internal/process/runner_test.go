package process

import (
	"context"
	"errors"
	"testing"
)

type FakeProcessRunner struct{ Binary string; Args []string; Output Output; Err error }
func(f *FakeProcessRunner)Run(_ context.Context,binary string,args ...string)(Output,error){f.Binary=binary;f.Args=append([]string(nil),args...);return f.Output,f.Err}
func(f *FakeProcessRunner)RunInDir(ctx context.Context,_ string,binary string,args ...string)(Output,error){return f.Run(ctx,binary,args...)}
func TestFakeProcessRunnerDoesNotExecute(t *testing.T){fake:=&FakeProcessRunner{Err:errors.New("synthetic")};_,err:=fake.Run(context.Background(),"nmap","--version");if err==nil||fake.Binary!="nmap"{t.Fatal("fake runner did not capture invocation")}}
