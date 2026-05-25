//go:build windows

package carrier

import (
	"os"
	"syscall"
	"unsafe"
)

const (
	moveFileReplaceExisting = 0x1
	moveFileWriteThrough    = 0x8
)

var (
	kernel32    = syscall.NewLazyDLL("kernel32.dll")
	moveFileExW = kernel32.NewProc("MoveFileExW")
)

func replaceFileAtomic(tmpPath, path string) error {
	oldName, err := syscall.UTF16PtrFromString(tmpPath)
	if err != nil {
		return err
	}
	newName, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	r1, _, callErr := moveFileExW.Call(
		uintptr(unsafe.Pointer(oldName)),
		uintptr(unsafe.Pointer(newName)),
		uintptr(moveFileReplaceExisting|moveFileWriteThrough),
	)
	if r1 != 0 {
		return nil
	}
	if callErr != syscall.Errno(0) {
		return callErr
	}
	return os.Rename(tmpPath, path)
}

func syncParentDir(string) error {
	return nil
}
