//go:build windows

package main

import (
	"block-ads/eradication"
	"block-ads/settings"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/AzureIvory/winui/core"
	"github.com/AzureIvory/winui/widgets"
)

func (u *nativeUI) buildEradicationControls() {
	u.chkEradication = widgets.NewCheckBox("eradication-mode", "根除模式", widgets.ModeCustom)
	u.chkEradication.SetStyle(u.checkStyle())
	u.chkEradication.SetOnChange(u.changeEradicationMode)
	u.eradicationHint = u.label("eradication-hint", "", 12, 400, u.col(103, 116, 145), dtWordBreak)
	u.eradicationHint.SetMultiline(true)
	u.eradicationHint.SetWordWrap(true)
	u.btnCases = widgets.NewButton("eradication-cases", "根除记录", widgets.ModeCustom)
	u.btnCases.SetStyle(u.sidebarActionStyle())
	u.btnCases.SetOnClick(func() { u.showDialog(u.casesDialog); u.reloadCaseReports() })
	u.header.Add(u.chkEradication)
	u.sidebar.AddAll(u.eradicationHint, u.btnCases)
}

func (u *nativeUI) refreshEradicationMode() {
	cfg, err := settings.Load(filepath.Join(u.dir, "config.json"))
	u.chkEradication.SetChecked(cfg.EradicationMode == settings.AutoQuarantine)
	u.chkEradication.SetEnabled(!u.status.Run && err == nil)
	if err != nil {
		u.eradicationHint.SetText("配置读取失败：" + err.Error())
		return
	}
	text := "关闭：仅拦截进程\n开启：自动隔离并删除高置信度命中文件"
	if u.status.Run {
		text += "\n停止拦截后可切换"
	} else {
		text += "\n下次启动生效"
	}
	u.eradicationHint.SetText(text)
}

func (u *nativeUI) changeEradicationMode(on bool) {
	if u.currentStatus().Run {
		u.refreshStatus(u.currentStatus())
		u.showMessage("请先停止拦截再切换根除模式。", true)
		return
	}
	if on && !u.confirm("开启根除模式后，会自动隔离并删除 AppData 内的高置信度命中 EXE/DLL，并移除精确关联的启动项。\n关闭时仅保留原有进程拦截。是否开启？") {
		u.refreshEradicationMode()
		return
	}
	mode := settings.Intercept
	if on {
		mode = settings.AutoQuarantine
	}
	if err := settings.SaveMode(filepath.Join(u.dir, "config.json"), mode); err != nil {
		u.showMessage("保存模式失败："+err.Error(), true)
		u.refreshEradicationMode()
		return
	}
	u.refreshEradicationMode()
	u.showMessage("模式已保存，下次启动拦截时生效。", false)
}

func (u *nativeUI) buildCasesDialog() {
	u.casesDialog = u.newDialog("eradication-cases-dialog")
	u.casesTitle = u.label("cases-title", "根除记录", 18, 700, u.col(23, 33, 61), core.DTEndEllipsis)
	u.casesList = widgets.NewListBox("cases-list")
	u.casesList.SetStyle(u.ruleListStyle())
	u.casesList.SetOnChange(func(index int, item widgets.ListItem) {
		if index < 0 || index >= len(u.caseReports) {
			return
		}
		u.caseSelected = u.caseReports[index].ID
		u.casesDetail.SetText(formatCaseReport(u.caseReports[index]))
	})
	u.casesDetail = widgets.NewEditBox("cases-detail", widgets.ModeCustom)
	u.casesDetail.SetStyle(u.editStyle())
	u.casesDetail.SetMultiline(true)
	u.casesDetail.SetWordWrap(true)
	u.casesDetail.SetVerticalScroll(true)
	u.casesDetail.SetReadOnly(true)
	u.casesClose = widgets.NewButton("cases-close", "关闭", widgets.ModeCustom)
	u.casesClose.SetStyle(u.softButtonStyle())
	u.casesClose.SetOnClick(u.hideDialogs)
	u.casesRefresh = widgets.NewButton("cases-refresh", "刷新", widgets.ModeCustom)
	u.casesRefresh.SetStyle(u.primaryButtonStyle())
	u.casesRefresh.SetOnClick(u.reloadCaseReports)
	u.casesDialog.AddAll(u.casesTitle, u.casesList, u.casesDetail, u.casesRefresh, u.casesClose)
	u.registerDialog(u.casesDialog)
}

func (u *nativeUI) layoutCasesDialog(w, h int32) {
	dw, dh := u.dp(760), u.dp(560)
	if dw > w-u.dp(32) {
		dw = w - u.dp(32)
	}
	if dh > h-u.dp(32) {
		dh = h - u.dp(32)
	}
	r := core.Rect{X: (w - dw) / 2, Y: (h - dh) / 2, W: dw, H: dh}
	u.casesDialog.SetBounds(r)
	u.casesTitle.SetBounds(core.Rect{X: r.X + u.dp(20), Y: r.Y + u.dp(16), W: dw - u.dp(40), H: u.dp(30)})
	u.casesList.SetBounds(core.Rect{X: r.X + u.dp(20), Y: r.Y + u.dp(56), W: dw - u.dp(40), H: u.dp(150)})
	u.casesDetail.SetBounds(core.Rect{X: r.X + u.dp(20), Y: r.Y + u.dp(218), W: dw - u.dp(40), H: dh - u.dp(286)})
	u.casesRefresh.SetBounds(core.Rect{X: r.X + dw - u.dp(188), Y: r.Y + dh - u.dp(52), W: u.dp(76), H: u.dp(34)})
	u.casesClose.SetBounds(core.Rect{X: r.X + dw - u.dp(100), Y: r.Y + dh - u.dp(52), W: u.dp(76), H: u.dp(34)})
}

func (u *nativeUI) reloadCaseReports() {
	go func() {
		reports, issues, err := eradication.ListCaseReports(u.dir, 100)
		_ = u.app.Post(func() { u.applyCaseReports(reports, issues, err) })
	}()
}

func (u *nativeUI) applyCaseReports(reports []eradication.CaseReport, issues []eradication.CaseReadIssue, err error) {
	u.caseReports = reports
	if u.activeDialog != u.casesDialog {
		return
	}
	if err != nil {
		u.casesTitle.SetText("根除记录：读取失败")
		u.casesDetail.SetText(err.Error())
		return
	}
	u.casesTitle.SetText(fmt.Sprintf("根除记录 · 最近 %d 条 · %d 条读取异常", len(reports), len(issues)))
	items := make([]widgets.ListItem, 0, len(reports))
	selected := 0
	for i, r := range reports {
		items = append(items, widgets.ListItem{Value: r.ID, Text: r.StartedAt.Local().Format("01-02 15:04:05") + "  [" + caseStateLabel(r.Status) + "]  " + baseName(r.Image)})
		if r.ID == u.caseSelected {
			selected = i
		}
	}
	u.casesList.SetItems(items)
	if len(reports) > 0 {
		u.casesList.SetSelected(selected)
		u.caseSelected = reports[selected].ID
		u.casesDetail.SetText(formatCaseReport(reports[selected]))
	} else {
		u.caseSelected = ""
		u.casesDetail.SetText("暂无根除记录。仅拦截模式不生成根除 case。")
	}
	if len(issues) > 0 {
		var b strings.Builder
		b.WriteString("以下记录无法读取，请保留现场检查：\r\n")
		for _, issue := range issues {
			fmt.Fprintf(&b, "%s：%s\r\n", issue.File, issue.Error)
		}
		u.casesDetail.SetText(u.casesDetail.Text + "\r\n\r\n" + b.String())
	}
}

func caseStateLabel(state string) string {
	labels := map[string]string{"pending": "待处理", "pending_verification": "待验证", "pending_reboot": "待重启删除", "partial_failure": "发现残留", "review": "需人工检查", "restored": "已恢复", "released": "已释放关联", "partial_restore": "恢复未完成", "observing": "观察中", "completed": "窗口观察通过", "interrupted": "观察中断", "incomplete": "未能完整确认", "failed": "失败", "passed": "检查通过", "verified": "已确认", "quarantined": "已隔离", "linked": "共享关联", "removed": "已移除", "experimental_review": "仅记录，需人工检查", "absent": "未观察到", "present": "仍存在或已重现", "unknown": "无法确认"}
	if text, ok := labels[state]; ok {
		return text
	}
	if state == "" {
		return "未记录"
	}
	return state
}

func formatCaseReport(r eradication.CaseReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "程序：%s\r\n状态：%s\r\n时间：%s\r\n退出确认：%s\r\n观察：%s（%d 次采样）\r\n", r.Image, caseStateLabel(r.Status), r.StartedAt.Local().Format("2006-01-02 15:04:05"), caseStateLabel(r.ProcessExit), caseStateLabel(r.ObservationStatus), r.ObservationSamples)
	if r.RequiresReboot {
		b.WriteString("仍需重启后核对，尚不能认定根除完成。\r\n")
	}
	if r.RequiresObservation {
		b.WriteString("仍需完成观察。\r\n")
	}
	if r.ObservationReason != "" {
		fmt.Fprintf(&b, "观察说明：%s\r\n", r.ObservationReason)
	}
	for _, err := range r.Errors {
		fmt.Fprintf(&b, "诊断：%s\r\n", err)
	}
	for _, items := range []struct {
		name  string
		items []eradication.ReportItem
	}{{"文件", r.Artifacts}, {"持久化", r.Persistence}} {
		for _, item := range items.items {
			fmt.Fprintf(&b, "\r\n%s [%s] %s\r\n%s\r\n", items.name, caseStateLabel(item.Status), item.Kind, item.Path)
			if item.Error != "" {
				fmt.Fprintf(&b, "原因：%s\r\n", item.Error)
			}
		}
	}
	for _, check := range r.Checks {
		fmt.Fprintf(&b, "\r\n%s [%s] %s\r\n%s\r\n", check.At.Local().Format("15:04:05"), caseStateLabel(check.Outcome), check.Kind, check.Evidence)
		if check.Error != "" {
			fmt.Fprintf(&b, "错误：%s\r\n", check.Error)
		}
	}
	fmt.Fprintf(&b, "\r\n记录 ID：%s", r.ID)
	return b.String()
}
