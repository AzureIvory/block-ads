//go:build windows

package main

import (
	"block-ads-ui/utils"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/AzureIvory/winui/core"
	"github.com/AzureIvory/winui/widgets"
)

func (u *nativeUI) buildDialogs() {
	u.buildAddDialog()
	u.buildAlertDialog()
	u.buildAboutDialog()
	u.buildFakeConfirmDialog()
	u.buildUpdateDialog()
	u.buildSyncDialog()
	u.buildUploadDialog()
}

// buildAlertDialog 构建 winui 风格的提示弹窗
// 文本通过 alertBox 动态设置，复用同一实例。
func (u *nativeUI) buildAlertDialog() {
	u.alertDialog = u.newDialog("alert-dialog")
	u.alertLabel = u.label("alert-label", "", 15, 400, u.col(76, 91, 119), dtWordBreak)
	u.alertLabel.SetMultiline(true)
	u.alertLabel.SetWordWrap(true)
	u.alertClose = widgets.NewButton("alert-close", "确定", widgets.ModeCustom)
	u.alertClose.SetStyle(u.primaryButtonStyle())
	u.alertClose.SetOnClick(func() {
		u.hideDialogs()
	})
	u.alertDialog.AddAll(u.alertLabel, u.alertClose)
	u.registerDialog(u.alertDialog)
}

// alertBox 用 winui 风格对话框显示提示。
func (u *nativeUI) alertBox(text string) {
	if u.alertLabel == nil {
		return
	}
	u.alertLabel.SetText(text)
	u.showDialog(u.alertDialog)
}

func (u *nativeUI) buildAddDialog() {
	u.addDialog = u.newDialog("add-dialog")
	u.addTitle = u.label("add-title", "新增规则", 20, 700, u.col(23, 33, 61), core.DTEndEllipsis)
	u.addHint = u.label("add-hint", "请输入要新增的内容。", 14, 400, u.col(103, 116, 145), dtWordBreak)
	u.addInput = widgets.NewEditBox("add-input", widgets.ModeCustom)
	u.addInput.SetPlaceholder("新增一行内容")
	u.addInput.SetStyle(u.editStyle())
	u.addInput.SetOnSubmit(func(string) {
		u.handleAdd()
	})
	u.addCancel = widgets.NewButton("add-cancel", "取消", widgets.ModeCustom)
	u.addCancel.SetStyle(u.softButtonStyle())
	u.addCancel.SetOnClick(func() {
		u.hideDialogs()
	})
	u.addConfirm = widgets.NewButton("add-confirm", "确定添加", widgets.ModeCustom)
	u.addConfirm.SetStyle(u.primaryButtonStyle())
	u.addConfirm.SetOnClick(u.handleAdd)

	u.addDialog.AddAll(u.addTitle, u.addHint, u.addInput, u.addCancel, u.addConfirm)
	u.registerDialog(u.addDialog)
}


// tryRemoveSelectedLog 尝试卸载（查找并运行卸载程序）。
func (u *nativeUI) tryRemoveSelectedLog() {
	row, ok := u.currentLogRow()
	if !ok {
		return
	}
	p := strings.TrimSpace(row.Path)
	if p == "" {
		return
	}
	u.showMessage("尝试卸载中...", false)
	go func() {
		err := utils.Tryrm(p)
		_ = u.app.Post(func() {
			if err != nil {
				u.showMessage("尝试卸载失败: "+err.Error(), true)
				return
			}
			u.showMessage("已尝试卸载: "+p, false)
		})
	}()
}

// forceDeleteSelectedLog 强制删除文件。
func (u *nativeUI) forceDeleteSelectedLog() {
	row, ok := u.currentLogRow()
	if !ok {
		return
	}
	p := strings.TrimSpace(row.Path)
	if p == "" {
		return
	}
	u.showMessage("强制删除中...", false)
	go func() {
		err := utils.Del(p)
		_ = u.app.Post(func() {
			if err != nil {
				u.showMessage("强制删除失败: "+err.Error(), true)
				return
			}
			u.showMessage("已强制删除: "+p, false)
		})
	}()
}

func (u *nativeUI) buildAboutDialog() {
	u.aboutDialog = u.newDialog("about-dialog")
	u.aboutTitle = u.label("about-title", "关于", 20, 700, u.col(23, 33, 61), core.DTEndEllipsis)
	u.aboutIcon = widgets.NewImage("about-icon")
	u.aboutIcon.SetScaleMode(widgets.ImageScaleContain)
	if len(assetIconPNG) > 0 {
		_ = u.aboutIcon.LoadBytes(assetIconPNG)
	}
	u.aboutName = u.label("about-name", "block-ads", 28, 700, u.col(47, 104, 243), core.DTCenter|core.DTEndEllipsis)
	u.aboutDesc = u.label("about-desc", "简单、高效的流氓软件拦截工具", 15, 400, u.col(76, 91, 119), core.DTCenter|dtWordBreak)
	u.aboutVersion = u.label("about-version", "Version "+aboutVersionValue, 15, 500, u.col(103, 116, 145), core.DTCenter|core.DTEndEllipsis)
	u.aboutGit = widgets.NewButton("about-git", "GitHub", widgets.ModeCustom)
	u.aboutGit.SetStyle(u.softButtonStyle())
	u.aboutGit.SetKind(widgets.BtnLeft)
	u.aboutGit.SetImage(u.gitImage)
	u.aboutGit.SetOnClick(u.handleGit)
	u.aboutClose = widgets.NewButton("about-close", "关闭", widgets.ModeCustom)
	u.aboutClose.SetStyle(u.primaryButtonStyle())
	u.aboutClose.SetOnClick(func() {
		u.hideDialogs()
	})

	u.aboutDialog.AddAll(u.aboutTitle, u.aboutIcon, u.aboutName, u.aboutDesc, u.aboutVersion, u.aboutGit, u.aboutClose)
	u.registerDialog(u.aboutDialog)
}

func (u *nativeUI) buildFakeConfirmDialog() {
	u.fakeConfirmDialog = u.newDialog("fake-confirm-dialog")
	u.fakeConfirmTitle = u.label("fake-confirm-title", "一键伪装", 20, 700, u.col(23, 33, 61), core.DTEndEllipsis)
	u.fakeConfirmMessage = u.label("fake-confirm-message", fakeConfirmMessage, 14, 400, u.col(76, 91, 119), dtWordBreak)
	u.fakeConfirmMessage.SetMultiline(true)
	u.fakeConfirmMessage.SetWordWrap(true)
	u.fakeConfirmContinue = widgets.NewButton("fake-confirm-continue", "继续", widgets.ModeCustom)
	u.fakeConfirmContinue.SetStyle(u.primaryButtonStyle())
	u.fakeConfirmContinue.SetOnClick(func() {
		u.hideDialogs()
		u.runFakeAsync()
	})
	u.fakeConfirmCancel = widgets.NewButton("fake-confirm-cancel", "取消", widgets.ModeCustom)
	u.fakeConfirmCancel.SetStyle(u.softButtonStyle())
	u.fakeConfirmCancel.SetOnClick(func() {
		u.hideDialogs()
	})

	u.fakeConfirmDialog.AddAll(
		u.fakeConfirmTitle,
		u.fakeConfirmMessage,
		u.fakeConfirmCancel,
		u.fakeConfirmContinue,
	)
	u.registerDialog(u.fakeConfirmDialog)
}

func (u *nativeUI) buildUpdateDialog() {
	u.updateDialog = u.newDialog("update-dialog")
	u.updateTitle = u.label("update-title", "更新", 20, 700, u.col(23, 33, 61), core.DTEndEllipsis)
	u.updateVersion = u.label("update-version", "本地 v- -> 在线 v-", 15, 600, u.col(47, 104, 243), core.DTEndEllipsis)
	u.updateDate = u.label("update-date", "更新日期: -", 14, 500, u.col(103, 116, 145), core.DTEndEllipsis)
	u.updateNotes = u.label("update-notes", "更新说明: -", 13, 400, u.col(76, 91, 119), dtWordBreak)
	u.updateItems = u.label("update-items", "", 13, 400, u.col(76, 91, 119), dtWordBreak)
	u.updateCheck = widgets.NewButton("update-check", "检测更新", widgets.ModeCustom)
	u.updateCheck.SetStyle(u.softButtonStyle())
	u.updateCheck.SetOnClick(func() {
		u.checkUpdateAsync(true)
	})
	u.updateGo = widgets.NewButton("update-go", "立即更新", widgets.ModeCustom)
	u.updateGo.SetStyle(u.primaryButtonStyle())
	u.updateGo.SetOnClick(u.doUpdateAsync)
	u.updateClose = widgets.NewButton("update-close", "关闭", widgets.ModeCustom)
	u.updateClose.SetStyle(u.softButtonStyle())
	u.updateClose.SetOnClick(func() {
		u.hideDialogs()
	})
	u.updateWait = u.newWaitAnim()

	u.updateDialog.AddAll(
		u.updateTitle,
		u.updateVersion,
		u.updateDate,
		u.updateNotes,
		u.updateItems,
		u.updateCheck,
		u.updateGo,
		u.updateClose,
		u.updateWait,
	)
	u.registerDialog(u.updateDialog)
}

func (u *nativeUI) buildSyncDialog() {
	u.syncDialog = u.newDialog("sync-dialog")
	u.syncTitle = u.label("sync-title", "同步", 20, 700, u.col(23, 33, 61), core.DTEndEllipsis)
	u.syncDesc = u.label("sync-desc", "用于同步黑白名单与注释", 14, 400, u.col(103, 116, 145), dtWordBreak)
	u.syncDate = u.label("sync-date", "未检查", 14, 500, u.col(47, 104, 243), core.DTEndEllipsis)
	u.syncNotes = u.label("sync-notes", "", 14, 400, u.col(76, 91, 119), dtWordBreak)

	u.syncItemsPanel = widgets.NewPanel("sync-items")
	u.syncItemsPanel.SetStyle(widgets.PanelStyle{
		Background:   u.col(248, 251, 255),
		BorderColor:  u.col(224, 231, 243),
		CornerRadius: 14,
		BorderWidth:  1,
	})

	u.syncRadioSel = widgets.NewRadioButton("sync-radio-sel", "以后自动同步已勾选的项目", widgets.ModeCustom)
	u.syncRadioSel.SetGroup("sync-policy")
	u.syncRadioSel.SetStyle(u.radioStyle())
	u.syncRadioSel.SetChecked(true)
	u.syncRadioSel.SetOnChange(func(v bool) {
		if v {
			u.syncPolicy = "auto_selected"
			u.applySyncPolicyState()
		}
	})

	u.syncRadioAll = widgets.NewRadioButton("sync-radio-all", "以后自动同步所有项目", widgets.ModeCustom)
	u.syncRadioAll.SetGroup("sync-policy")
	u.syncRadioAll.SetStyle(u.radioStyle())
	u.syncRadioAll.SetOnChange(func(v bool) {
		if v {
			u.syncPolicy = "auto_all"
			u.applySyncPolicyState()
		}
	})

	u.syncRadioNever = widgets.NewRadioButton("sync-radio-never", "以后都不同步", widgets.ModeCustom)
	u.syncRadioNever.SetGroup("sync-policy")
	u.syncRadioNever.SetStyle(u.radioStyle())
	u.syncRadioNever.SetOnChange(func(v bool) {
		if v {
			u.syncPolicy = "never"
			u.applySyncPolicyState()
		}
	})

	u.syncCheck = widgets.NewButton("sync-check", "检查同步", widgets.ModeCustom)
	u.syncCheck.SetStyle(u.softButtonStyle())
	u.syncCheck.SetOnClick(func() {
		u.checkSyncAsync(true)
	})

	u.syncGo = widgets.NewButton("sync-go", "开始同步", widgets.ModeCustom)
	u.syncGo.SetStyle(u.primaryButtonStyle())
	u.syncGo.SetOnClick(u.doSyncAsync)

	u.syncClose = widgets.NewButton("sync-close", "关闭", widgets.ModeCustom)
	u.syncClose.SetStyle(u.softButtonStyle())
	u.syncClose.SetOnClick(func() {
		u.hideDialogs()
	})
	u.syncWait = u.newWaitAnim()

	u.syncDialog.AddAll(
		u.syncTitle,
		u.syncDesc,
		u.syncDate,
		u.syncNotes,
		u.syncItemsPanel,
		u.syncRadioSel,
		u.syncRadioAll,
		u.syncRadioNever,
		u.syncCheck,
		u.syncGo,
		u.syncClose,
		u.syncWait,
	)
	u.registerDialog(u.syncDialog)
}

func (u *nativeUI) buildUploadDialog() {
	u.uploadDialog = u.newDialog("upload-dialog")
	u.uploadTitle = u.label("upload-title", "上传信息", 20, 700, u.col(23, 33, 61), core.DTEndEllipsis)
	u.uploadDesc = u.label("upload-desc", "如果发现还有流氓软件没能结束，可以将本地信息上传到服务器分析。", 14, 400, u.col(76, 91, 119), dtWordBreak)
	u.uploadWarn = u.label("upload-warn", "注意：这里只用于完善名单库以优化拦截效果，不会上传您的文件。", 14, 500, u.col(220, 38, 38), dtWordBreak)

	u.uploadAll = widgets.NewCheckBox("upload-all", "全选", widgets.ModeCustom)
	u.uploadAll.SetStyle(u.checkStyle())
	u.uploadAll.SetOnChange(func(v bool) {
		for key, cb := range u.uploadChecks {
			u.uploadChecked[key] = v
			cb.SetChecked(v)
		}
	})

	for _, opt := range uploadOptions {
		cb := widgets.NewCheckBox("upload-"+opt.Key, opt.Label, widgets.ModeCustom)
		cb.SetStyle(u.checkStyle())
		key := opt.Key
		cb.SetOnChange(func(v bool) {
			u.uploadChecked[key] = v
			u.refreshUploadAll()
		})
		u.uploadChecks[opt.Key] = cb
		u.uploadDialog.Add(cb)
	}

	u.uploadClose = widgets.NewButton("upload-close", "关闭", widgets.ModeCustom)
	u.uploadClose.SetStyle(u.softButtonStyle())
	u.uploadClose.SetOnClick(func() {
		u.hideDialogs()
	})
	u.uploadCancel = widgets.NewButton("upload-cancel", "取消", widgets.ModeCustom)
	u.uploadCancel.SetStyle(u.softButtonStyle())
	u.uploadCancel.SetOnClick(func() {
		u.hideDialogs()
	})
	u.uploadGo = widgets.NewButton("upload-go", "立即上传", widgets.ModeCustom)
	u.uploadGo.SetStyle(u.primaryButtonStyle())
	u.uploadGo.SetOnClick(u.doUploadAsync)

	u.uploadDialog.AddAll(
		u.uploadTitle,
		u.uploadDesc,
		u.uploadWarn,
		u.uploadAll,
		u.uploadClose,
		u.uploadCancel,
		u.uploadGo,
	)
	u.registerDialog(u.uploadDialog)
}

func (u *nativeUI) openAboutDialog() {
	u.refreshAboutVersion()
	u.showDialog(u.aboutDialog)
}

func (u *nativeUI) openUpdateDialog() {
	u.refreshUpdateDialog()
	u.showDialog(u.updateDialog)
	if u.lastUpdate == nil {
		u.checkUpdateAsync(false)
	}
}

func (u *nativeUI) openSyncDialog() {
	u.refreshSyncDialog()
	u.showDialog(u.syncDialog)
	if u.lastSync == nil {
		u.checkSyncAsync(false)
	}
}

func (u *nativeUI) openUploadDialog() {
	u.refreshUploadAll()
	u.showDialog(u.uploadDialog)
}

func (u *nativeUI) showDialog(dialog *widgets.Panel) {
	u.activeDialog = dialog
	u.mask.SetVisible(true)
	for _, panel := range u.dialogs {
		panel.SetVisible(panel == dialog)
	}
}

func (u *nativeUI) hideDialogs() {
	u.activeDialog = nil
	u.mask.SetVisible(false)
	for _, panel := range u.dialogs {
		panel.SetVisible(false)
	}
}

func (u *nativeUI) refreshAboutVersion() {
	if u.aboutVersion == nil {
		return
	}
	u.aboutVersion.SetText("Version " + aboutVersionValue)
}

func (u *nativeUI) refreshUpdateDialog() {
	if u.lastUpdate == nil {
		u.updateVersion.SetText("本地 v- -> 在线 v-")
		u.updateDate.SetText("更新日期: -")
		u.updateNotes.SetText("更新说明: -")
		u.updateItems.SetText("")
		u.updateGo.SetEnabled(false)
		return
	}
	info := u.lastUpdate
	u.updateVersion.SetText(fmt.Sprintf("本地 v%s -> 在线 v%s", emptyAs(info.LocVer, "-"), emptyAs(info.SrvVer, "-")))
	u.updateDate.SetText("更新日期: " + emptyAs(info.UpdAt, "-"))
	notes := strings.TrimSpace(info.Notes)
	if notes == "" {
		notes = "无"
	}
	u.updateNotes.SetText("更新说明:\n" + notes)
	lines := make([]string, 0, len(info.Items))
	for _, it := range info.Items {
		state := "已最新"
		if it.Need {
			state = "需更新"
		}
		lines = append(lines, fmt.Sprintf("%s  %s  %s", it.Name, emptyAs(it.SizeText, "-"), state))
	}
	u.updateItems.SetText(strings.Join(lines, "\n"))
	u.updateGo.SetEnabled(info.HasUpd)
}

func (u *nativeUI) refreshSyncDialog() {
	if u.lastSync == nil {
		u.syncDate.SetText("未检查")
		u.syncNotes.SetText("")
		u.rebuildSyncChecks(nil)
		return
	}
	info := u.lastSync
	u.syncDate.SetText("同步日期: " + emptyAs(info.UpdAt, "-"))
	u.syncNotes.SetText(strings.TrimSpace(info.Notes))
	u.rebuildSyncChecks(info.Items)
}

func (u *nativeUI) refreshUploadAll() {
	allChecked := true
	for _, opt := range uploadOptions {
		if !u.uploadChecked[opt.Key] {
			allChecked = false
			break
		}
	}
	u.uploadAll.SetChecked(allChecked)
}

func (u *nativeUI) rebuildSyncChecks(items []SyncItemInfo) {
	clearPanelChildren(u.syncItemsPanel)
	u.syncChecks = nil
	if len(items) == 0 {
		lbl := u.label("sync-empty", "暂无同步项。", 14, 400, u.col(120, 132, 158), core.DTCenter|core.DTVCenter|core.DTSingleLine)
		u.syncItemsPanel.Add(lbl)
		lbl.SetBounds(core.Rect{
			X: u.syncItemsPanel.Bounds().X + u.dp(12),
			Y: u.syncItemsPanel.Bounds().Y + u.dp(54),
			W: u.syncItemsPanel.Bounds().W - u.dp(24),
			H: u.dp(24),
		})
		return
	}

	for _, item := range items {
		if _, ok := u.syncSelected[item.Name]; !ok {
			u.syncSelected[item.Name] = item.Need
		}
	}

	for _, item := range items {
		txt := fmt.Sprintf("%s  %s  %s", item.Name, emptyAs(item.SizeText, "-"), ternary(item.Need, "需同步", "已同步"))
		cb := widgets.NewCheckBox("sync-"+item.Name, txt, widgets.ModeCustom)
		cb.SetStyle(u.checkStyle())
		cb.SetChecked(u.syncSelected[item.Name])
		name := item.Name
		cb.SetOnChange(func(v bool) {
			u.syncSelected[name] = v
		})
		u.syncItemsPanel.Add(cb)
		u.syncChecks = append(u.syncChecks, cb)
	}
	u.layoutSyncChecks()
	u.applySyncPolicyState()
}

func (u *nativeUI) applySyncPolicyState() {
	for _, cb := range u.syncChecks {
		name := strings.TrimPrefix(cb.ID(), "sync-")
		switch u.syncPolicy {
		case "auto_all":
			u.syncSelected[name] = true
			cb.SetChecked(true)
			cb.SetEnabled(false)
		case "never":
			u.syncSelected[name] = false
			cb.SetChecked(false)
			cb.SetEnabled(false)
		default:
			cb.SetEnabled(true)
			cb.SetChecked(u.syncSelected[name])
		}
	}
}

func (u *nativeUI) layoutSyncChecks() {
	if u.syncItemsPanel == nil {
		return
	}
	b := u.syncItemsPanel.Bounds()
	x := b.X + u.dp(16)
	w := b.W - u.dp(32)
	for idx, cb := range u.syncChecks {
		cb.SetBounds(core.Rect{
			X: x,
			Y: b.Y + u.dp(12) + int32(idx)*u.dp(28),
			W: w,
			H: u.dp(24),
		})
	}
}

func (u *nativeUI) selectedSyncNames() []interface{} {
	out := make([]interface{}, 0, len(u.syncSelected))
	for name, checked := range u.syncSelected {
		if checked {
			out = append(out, name)
		}
	}
	return out
}

func (u *nativeUI) selectedUploadNames() []string {
	out := make([]string, 0, len(u.uploadChecked))
	for _, opt := range uploadOptions {
		if u.uploadChecked[opt.Key] {
			out = append(out, opt.Key)
		}
	}
	return out
}

func (u *nativeUI) uploadSelected(sel []string) (string, error) {
	set := make(map[string]bool, len(sel))
	for _, key := range sel {
		set[key] = true
	}
	u.dat.mu.Lock()
	kws := append([]string(nil), u.dat.lst["folder"]...)
	u.dat.mu.Unlock()
	up := mkUp(set, kws)
	body, err := json.Marshal(up)
	if err != nil {
		return "", err
	}
	return utils.UpPost(upUrl, body)
}

func (u *nativeUI) confirm(text string) bool {
	if u.app != nil {
		ret, err := u.app.MessageBox("提示", text, 0x00000001|0x00000030, 0)
		if err == nil {
			return ret == 1
		}
	}
	return utils.PopMsg("提示", text, 0x00000001, 0x00000030) == 1
}

func (u *nativeUI) registerDialog(dialog *widgets.Panel) {
	dialog.SetVisible(false)
	u.dialogs = append(u.dialogs, dialog)
	u.root.Add(dialog)
}

func (u *nativeUI) newDialog(id string) *widgets.Panel {
	panel := widgets.NewPanel(id)
	panel.SetStyle(widgets.PanelStyle{
		Background:   u.col(255, 255, 255),
		BorderColor:  u.col(221, 228, 241),
		CornerRadius: 18,
		BorderWidth:  1,
	})
	return panel
}

func (u *nativeUI) checkUpdateAsync(showMsg bool) {
	if showMsg {
		u.showMessage("检测更新中...", false)
	}
	u.setUpdateWaiting(true)
	go func() {
		info, err := u.dat.ChkUpd()
		_ = u.app.Post(func() {
			u.setUpdateWaiting(false)
			if err != nil {
				u.showMessage("检测更新失败: "+err.Error(), true)
				return
			}
			u.lastUpdate = &info
			u.refreshUpdateDialog()
			if showMsg {
				if info.HasUpd {
					u.showMessage("发现新版本。", false)
				} else {
					u.showMessage("已是最新版本。", false)
				}
			}
		})
	}()
}

func (u *nativeUI) doUpdateAsync() {
	if u.lastUpdate == nil {
		u.checkUpdateAsync(true)
		return
	}
	if !u.lastUpdate.HasUpd {
		u.showMessage("未发现可更新内容。", false)
		return
	}
	if !u.confirm("开始更新后界面将关闭，是否继续？") {
		return
	}
	u.showMessage("更新中...", false)
	u.setUpdateWaiting(true)
	go func() {
		started, err := u.dat.DoUpdNative(func() {
			time.Sleep(250 * time.Millisecond)
			u.app.Close()
		})
		_ = u.app.Post(func() {
			u.setUpdateWaiting(false)
			if err != nil {
				u.showMessage("更新失败: "+err.Error(), true)
				return
			}
			if !started {
				u.showMessage("没有需要更新的文件。", false)
				return
			}
			u.showMessage("已启动更新，程序即将关闭。", false)
		})
	}()
}

func (u *nativeUI) checkSyncAsync(showMsg bool) {
	if showMsg {
		u.showMessage("检查同步中...", false)
	}
	u.setSyncWaiting(true)
	go func() {
		info, err := u.dat.ChkSyn()
		_ = u.app.Post(func() {
			u.setSyncWaiting(false)
			if err != nil {
				u.showMessage("检查同步失败: "+err.Error(), true)
				return
			}
			u.lastSync = &info
			u.refreshSyncDialog()
			if showMsg {
				u.showMessage("同步检查完成。", false)
			}
		})
	}()
}

func (u *nativeUI) doSyncAsync() {
	if u.syncPolicy == "never" {
		u.showMessage("同步已关闭。", true)
		return
	}
	req := map[string]interface{}{
		"policy":   u.syncPolicy,
		"selected": u.selectedSyncNames(),
	}
	u.showMessage("同步中...", false)
	u.setSyncWaiting(true)
	go func() {
		ok, err := u.dat.DoSyn(req)
		_ = u.app.Post(func() {
			u.setSyncWaiting(false)
			if err != nil {
				u.showMessage("同步失败: "+err.Error(), true)
				return
			}
			u.reloadData()
			u.checkSyncAsync(false)
			if ok {
				u.showMessage("同步完成。", false)
			} else {
				u.showMessage("没有需要同步的内容。", false)
			}
		})
	}()
}

func (u *nativeUI) doUploadAsync() {
	names := u.selectedUploadNames()
	if len(names) == 0 {
		u.showMessage("请选择需要上传的项目。", true)
		return
	}
	u.showMessage("开始上传...", false)
	go func() {
		url, err := u.uploadSelected(names)
		_ = u.app.Post(func() {
			if err != nil {
				u.showMessage("上传失败: "+err.Error(), true)
				return
			}
			msg := "上传成功。"
			if url != "" {
				msg += " " + url
			}
			u.showMessage(msg, false)
		})
	}()
}
