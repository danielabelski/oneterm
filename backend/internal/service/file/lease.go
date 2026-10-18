package file

import (
	"sync"

	"github.com/pkg/sftp"
)

type leasedFile struct {
	*sftp.File
	release func()
	once    sync.Once
	err     error
}

func (f *leasedFile) Close() error {
	f.once.Do(func() { defer f.release(); f.err = f.File.Close() })
	return f.err
}
