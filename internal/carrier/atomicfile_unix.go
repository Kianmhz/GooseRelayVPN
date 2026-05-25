//go:build !windows

package carrier

import "os"

func replaceFileAtomic(tmpPath, path string) error {
	return os.Rename(tmpPath, path)
}

func syncParentDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return nil
	}
	defer d.Close()
	return d.Sync()
}
