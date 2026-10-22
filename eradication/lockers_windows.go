//go:build windows

package eradication

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Restart Manager reports a PID together with its creation time. A PID alone
// is never sufficient authorization to terminate a process.
type lockerProcess struct {
	PID     uint32
	Created windows.Filetime
}

type rmProcessInfo struct {
	PID              uint32
	Created          windows.Filetime
	AppName          [256]uint16
	ServiceShortName [64]uint16
	AppType          uint32
	AppStatus        uint32
	SessionID        uint32
	Restartable      int32
}

var (
	restartManagerDLL = windows.NewLazySystemDLL("rstrtmgr.dll")
	rmStartSession    = restartManagerDLL.NewProc("RmStartSession")
	rmEndSession      = restartManagerDLL.NewProc("RmEndSession")
	rmRegisterFiles   = restartManagerDLL.NewProc("RmRegisterResources")
	rmGetList         = restartManagerDLL.NewProc("RmGetList")
)

func rmError(action string, result uintptr) error {
	if result == 0 {
		return nil
	}
	return fmt.Errorf("%s: %w", action, syscall.Errno(result))
}

func enumerateLockers(path string) ([]lockerProcess, error) {
	var session uint32
	var key [33]uint16 // CCH_RM_SESSION_KEY + 1
	result, _, _ := rmStartSession.Call(uintptr(unsafe.Pointer(&session)), 0, uintptr(unsafe.Pointer(&key[0])))
	if err := rmError("RmStartSession", result); err != nil {
		return nil, err
	}
	defer rmEndSession.Call(uintptr(session))
	file, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	result, _, _ = rmRegisterFiles.Call(uintptr(session), 1, uintptr(unsafe.Pointer(&file)), 0, 0, 0, 0)
	if err := rmError("RmRegisterResources", result); err != nil {
		return nil, err
	}
	for attempt := 0; attempt < 3; attempt++ {
		var needed, count, reboot uint32
		result, _, _ = rmGetList.Call(uintptr(session), uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&count)), 0, uintptr(unsafe.Pointer(&reboot)))
		if result == 0 && needed == 0 {
			return nil, nil
		}
		if result != uintptr(windows.ERROR_MORE_DATA) && result != 0 {
			return nil, rmError("RmGetList", result)
		}
		if needed == 0 || needed > 256 {
			return nil, fmt.Errorf("Restart Manager reported %d locking processes", needed)
		}
		infos := make([]rmProcessInfo, needed)
		count = needed
		result, _, _ = rmGetList.Call(uintptr(session), uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&infos[0])), uintptr(unsafe.Pointer(&reboot)))
		if result == uintptr(windows.ERROR_MORE_DATA) {
			continue
		}
		if err := rmError("RmGetList", result); err != nil {
			return nil, err
		}
		if count > uint32(len(infos)) {
			return nil, fmt.Errorf("Restart Manager returned %d processes into %d slots", count, len(infos))
		}
		lockers := make([]lockerProcess, 0, count)
		for _, info := range infos[:count] {
			if info.PID == 0 || info.PID == 4 || info.PID == uint32(os.Getpid()) || info.AppType == 3 || info.AppType == 4 || info.AppType == 1000 {
				continue // services, Explorer and critical processes are never terminated here
			}
			lockers = append(lockers, lockerProcess{PID: info.PID, Created: info.Created})
		}
		return lockers, nil
	}
	return nil, errors.New("Restart Manager locker list changed repeatedly")
}

func openAuthorizedLocker(locker lockerProcess, hit HitEvent) (windows.Handle, error) {
	if locker.PID == 0 || locker.PID == 4 || locker.PID == uint32(os.Getpid()) ||
		locker.Created.HighDateTime == 0 && locker.Created.LowDateTime == 0 ||
		!inUserAppData(hit.Image) || hit.FileID == "" {
		return 0, fmt.Errorf("locker lacks a safe process or artifact identity")
	}
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, locker.PID)
	if err != nil {
		return 0, err
	}
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil || created != locker.Created {
		windows.CloseHandle(h)
		return 0, fmt.Errorf("locker PID %d creation time changed: %v", locker.PID, err)
	}
	path, err := processPath(h)
	if err != nil || !samePath(path, hit.Image) {
		windows.CloseHandle(h)
		return 0, fmt.Errorf("locker PID %d image is outside the matched executable: %v", locker.PID, err)
	}
	fileID, err := FileID(path)
	if err != nil || fileID != hit.FileID {
		windows.CloseHandle(h)
		return 0, fmt.Errorf("locker PID %d image file identity differs: %v", locker.PID, err)
	}
	return h, nil
}

func terminateVerifiedLocker(h windows.Handle) error {
	if event, err := windows.WaitForSingleObject(h, 0); err == nil && event == windows.WAIT_OBJECT_0 {
		return nil
	}
	if err := windows.TerminateProcess(h, 1); err != nil {
		return err
	}
	event, err := windows.WaitForSingleObject(h, 5000)
	if err != nil || event != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("locker exit not verified: event=%d error=%v", event, err)
	}
	return nil
}

func scheduleDeleteAtReboot(path string) error {
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(ptr, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
}
