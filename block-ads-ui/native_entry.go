//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

func main() {
	if len(os.Args) >= 3 && os.Args[1] == "--apply-update" {
		pendPth := os.Args[2]

		waitPID := 0
		for i := 3; i < len(os.Args); i++ {
			if os.Args[i] == "--wait-pid" && i+1 < len(os.Args) {
				if v, err := strconv.Atoi(os.Args[i+1]); err == nil {
					waitPID = v
				}
				i++
			}
		}

		if err := AppPend(pendPth, waitPID); err != nil {
			fmt.Println("apply update failed:", err)
		}
		return
	}

	exePath, err := os.Executable()
	if err != nil {
		panic(err)
	}
	dir := filepath.Dir(exePath)
	_ = os.Remove(filepath.Join(dir, ".updater_tmp.exe"))

	if err := runNativeUI(newDat(dir), dir); err != nil {
		panic(err)
	}
}
