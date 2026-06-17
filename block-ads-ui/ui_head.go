//go:build windows

package main

import (
	"block-ads-ui/utils"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/AzureIvory/winui/core"
	"github.com/AzureIvory/winui/widgets"
)

func (u *nativeUI) buildHeader() {
	u.brandLabel = u.label("brand", "名单管理", 22, 700, u.col(35, 87, 230), core.DTVCenter|core.DTSingleLine)
	u.adminLabel = u.label("admin", "管理员", 12, 600, u.col(22, 163, 74), core.DTCenter|core.DTVCenter|core.DTSingleLine)
	u.runLabel = u.label("run-state", "未运行", 12, 600, u.col(120, 132, 158), core.DTCenter|core.DTVCenter|core.DTSingleLine)

	u.btnRun = widgets.NewButton("run", "启动", widgets.ModeCustom)
	u.btnRun.SetStyle(u.primaryButtonStyle())
	u.btnRun.SetKind(widgets.BtnLeft)
	u.btnRun.SetImage(u.startImage)
	u.btnRun.SetOnClick(u.handleToggleRun)

	u.chkBoot = widgets.NewCheckBox("boot", "拦截自启", widgets.ModeCustom)
	u.chkBoot.SetStyle(u.checkStyle())
	u.chkBoot.SetOnChange(func(v bool) {
		u.onAppBoot(v)
	})

	u.chkCode = widgets.NewCheckBox("code-boot", "伪装自启", widgets.ModeCustom)
	u.chkCode.SetStyle(u.checkStyle())
	u.chkCode.SetOnChange(func(v bool) {
		u.onCodeBoot(v)
	})

	u.btnFake = widgets.NewButton("fake", "一键伪装", widgets.ModeCustom)
	u.btnFake.SetStyle(u.headerIconButtonStyle())
	u.btnFake.SetKind(widgets.BtnLeft)
	u.btnFake.SetImage(u.fakeImage)
	u.btnFake.SetOnClick(u.handleFake)

	u.btnGit = widgets.NewButton("github", "GitHub", widgets.ModeCustom)
	u.btnGit.SetStyle(u.headerIconButtonStyle())
	u.btnGit.SetKind(widgets.BtnLeft)
	u.btnGit.SetImage(u.gitImage)
	u.btnGit.SetOnClick(u.handleGit)

	u.header.AddAll(
		u.brandLabel,
		u.btnRun,
		u.chkBoot,
		u.chkCode,
		u.adminLabel,
		u.runLabel,
		u.btnFake,
		u.btnGit,
	)
}

func (u *nativeUI) refreshStatus(st uiSta) {
	u.status = st
	u.chkBoot.SetChecked(st.Boot)
	u.chkCode.SetChecked(st.CodeBoot)
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
		if u.app != nil {
			u.app.SetTitle("名单管理 - 已运行")
		}
	} else {
		u.runLabel.SetText("未运行")
		u.runLabel.SetStyle(u.textStyle(12, 600, u.col(120, 132, 158), core.DTCenter|core.DTVCenter|core.DTSingleLine))
		u.serviceLabel.SetText("服务状态: 未运行")
		u.serviceLabel.SetStyle(u.textStyle(12, 500, u.col(120, 132, 158), core.DTEndEllipsis))
		u.btnRun.SetText("启动")
		u.btnRun.SetStyle(u.primaryButtonStyle())
		if u.app != nil {
			u.app.SetTitle("名单管理 - 未运行")
		}
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
				// 启动失败（含目标文件不存在）：弹窗提示具体原因。
				if os.IsNotExist(err) {
					u.alertBox("未找到拦截程序：\n" + u.exe)
				} else {
					u.alertBox("启动失败：\n" + err.Error())
				}
				u.showMessage("启动失败: "+err.Error(), true)
				return
			}
			u.refreshStatus(u.currentStatus())
			if u.status.Run {
				u.showMessage("启动成功。", false)
			} else {
				// 启动指令已发出但进程未运行（如被 UAC 拒绝、被拦截器拦下）。
				u.alertBox("启动未成功，拦截进程未运行。\n请检查是否被拒绝或被安全软件拦截。")
				u.showMessage("已尝试启动。", false)
			}
		})
	}()
}

func (u *nativeUI) onAppBoot(on bool) {
	u.showMessage("更新启动项...", false)
	go func() {
		err := setBootKey(runName, u.exe, on)
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

func (u *nativeUI) onCodeBoot(on bool) {
	u.showMessage("更新 Code 启动项...", false)
	go func() {
		err := setBootKey(runNameCode, u.codeEx, on)
		_ = u.app.Post(func() {
			if err != nil {
				u.chkCode.SetChecked(!on)
				u.showMessage("设置失败: "+err.Error(), true)
				return
			}
			u.refreshStatus(u.currentStatus())
			u.showMessage("", false)
		})
	}()
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
		if !utils.HasProc(codeExeName) {
			cod := filepath.Join(u.dir, codeExeName)
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
