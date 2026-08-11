package platform

import (
	"runtime"
)

type Info struct{ OS, Architecture string }

func Current() Info { return Info{OS: runtime.GOOS, Architecture: runtime.GOARCH} }
