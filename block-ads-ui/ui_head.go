//go:build windows

package main

import (
	"block-ads-ui/utils"
	"github.com/AzureIvory/winui/core"
	"github.com/AzureIvory/winui/widgets"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func (u *nativeUI) buildHeader() {
	u.brandLabel = u.label("brand", "名单管理", 22, 700, u.col(35, 87, 230), core.DTVCenter|core.DTSingleLine)
	u.adminLabel = u.label("admin", "管理员", 12, 600, u.col(22, 163, 74), core.DTCenter|core.DTVCenter|core.DTSingleLine)
	u.runLabel = u.label("run-state", "未运行", 12, 600, u.col(120, 132, 158), core.DTCenter|core.DTVCenter|core.DTSingleLine)

	u.btnRun = widgets.NewButton("run", "启动", widgets.ModeCustom)
	u.btnRun.SetStyle(u.primaryButtonStyle())
	u.btnRun.SetOnClick(u.handleToggleRun)

	u.chkBoot = widgets.NewCheckBox("boot", "开机自启", widgets.ModeCustom)
	u.chkBoot.SetStyle(u.checkStyle())
	u.chkBoot.SetOnChange(func(v bool) {
		u.handleBootChange(v)
	})

	u.btnFake = widgets.NewButton("fake", "一键伪装", widgets.ModeCustom)
	u.btnFake.SetStyle(u.compactSoftButtonStyle())
	u.btnFake.SetOnClick(u.handleFake)

	u.btnGit = widgets.NewButton("github", "GitHub", widgets.ModeCustom)
	u.btnGit.SetStyle(u.compactSoftButtonStyle())
	u.btnGit.SetOnClick(u.handleGit)

	u.header.AddAll(
		u.brandLabel,
		u.btnRun,
		u.chkBoot,
		u.adminLabel,
		u.runLabel,
		u.btnFake,
		u.btnGit,
	)
}

func (u *nativeUI) refreshStatus(st uiSta) {
	u.status = st
	u.chkBoot.SetChecked(st.Boot)
	if st.Adm {
		u.adminLabel.SetText("管理员")
		u.adminLabel.SetStyle(u.textStyle(12, 600, u.col(22, 163, 74), core.DTCenter|core.DTVCenter|core.DTSingleLine))
	} else {
		u.adminLabel.SetText("普通用户")
		u.adminLabel.SetStyle(u.textStyle(12, 600, u.col(220, 38, 38), core.DTCenter|core.DTVCenter|core.DTSingleLine))
	}
	if st.Run {
		u.runLabel.SetText("已运行")
		u.runLabel.SetStyle(u.textStyle(12, 600, u.col(22, 163, 74), core.DTCenter|core.DTVCenter|core.DTSingleLine))
		u.serviceLabel.SetText("服务状态: 已运行")
		u.serviceLabel.SetStyle(u.textStyle(12, 500, u.col(22, 163, 74), core.DTEndEllipsis))
		u.btnRun.SetText("停止")
		u.btnRun.SetStyle(u.dangerButtonStyle())
		u.app.SetTitle("名单管理 - 已运行")
	} else {
		u.runLabel.SetText("未运行")
		u.runLabel.SetStyle(u.textStyle(12, 600, u.col(120, 132, 158), core.DTCenter|core.DTVCenter|core.DTSingleLine))
		u.serviceLabel.SetText("服务状态: 未运行")
		u.serviceLabel.SetStyle(u.textStyle(12, 500, u.col(120, 132, 158), core.DTEndEllipsis))
		u.btnRun.SetText("启动")
		u.btnRun.SetStyle(u.primaryButtonStyle())
		u.app.SetTitle("名单管理 - 未运行")
	}
	if st.Adm {
		u.modeLabel.SetText("Admin Mode")
	} else {
		u.modeLabel.SetText("User Mode")
	}
}

func (u *nativeUI) handleToggleRun() {
	if u.status.Run {
		if !u.confirm("是否停止拦截进程？") {
			return
		}
		u.showMessage("停止中...", false)
		go func() {
			err := stopAd(u.dir)
			time.Sleep(400 * time.Millisecond)
			_ = u.app.Post(func() {
				if err != nil {
					u.showMessage("停止失败: "+err.Error(), true)
				} else {
					u.refreshStatus(u.currentStatus())
					u.showMessage("已尝试停止。", false)
				}
			})
		}()
		return
	}

	u.showMessage("启动中...", false)
	go func() {
		err := runExe(u.exe)
		time.Sleep(700 * time.Millisecond)
		_ = u.app.Post(func() {
			if err != nil {
				u.showMessage("启动失败: "+err.Error(), true)
				return
			}
			u.refreshStatus(u.currentStatus())
			if u.status.Run {
				u.showMessage("启动成功。", false)
			} else {
				u.showMessage("已尝试启动。", false)
			}
		})
	}()
}

func (u *nativeUI) handleBootChange(on bool) {
	u.showMessage("更新启动项...", false)
	go func() {
		err := setBootKey(runName, u.exe, on)
		if err == nil {
			err = setBootKey(runNameCode, u.codeEx, on)
		}
		_ = u.app.Post(func() {
			if err != nil {
				u.chkBoot.SetChecked(!on)
				u.showMessage("设置失败: "+err.Error(), true)
				return
			}
			u.refreshStatus(u.currentStatus())
			u.showMessage("", false)
		})
	}()
}

func (u *nativeUI) handleHelp() {
	if err := goUrl("https://www.kdocs.cn/l/carLpeQqWued"); err != nil {
		u.showMessage("无法打开使用指南: "+err.Error(), true)
		return
	}
	u.showMessage("", false)
}

func (u *nativeUI) handleGit() {
	if err := goUrl("https://github.com/AzureIvory/block-ads"); err != nil {
		u.showMessage("无法打开 GitHub: "+err.Error(), true)
		return
	}
	u.showMessage("", false)
}

func (u *nativeUI) handleFake() {
	u.showDialog(u.fakeConfirmDialog)
}

func (u *nativeUI) runFakeAsync() {
	u.showMessage("伪装中...", false)
	go func() {
		errs := []string{}
		if !utils.HasProc("Code.exe") {
			cod := filepath.Join(u.dir, "Code.exe")
			cmd := exec.Command(cod)
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			cmd.Dir = u.dir
			if err := cmd.Start(); err != nil {
				errs = append(errs, err.Error())
			}
		}
		_ = goUrl("https://www.zhihu.com/")
		for _, fn := range []func() error{reghr, regvm, regvip, inivip, ads360} {
			if err := fn(); err != nil {
				errs = append(errs, err.Error())
			}
		}
		_ = u.app.Post(func() {
			if len(errs) > 0 {
				u.showMessage("伪装未完全成功: "+strings.Join(errs, " | "), true)
				return
			}
			u.showMessage("一键伪装已执行。", false)
		})
	}()
}
