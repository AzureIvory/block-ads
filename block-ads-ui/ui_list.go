//go:build windows

package main

import (
	"fmt"
	"github.com/AzureIvory/winui/core"
	"github.com/AzureIvory/winui/widgets"
	"strconv"
	"strings"
)

func (u *nativeUI) buildSidebar() {
	for _, key := range listOrder {
		btn := widgets.NewButton("tab-"+key, listTitle[key], widgets.ModeCustom)
		btn.SetStyle(u.sideButtonStyle(false))
		cur := key
		btn.SetOnClick(func() {
			u.switchList(cur)
		})
		u.sideButtons[key] = btn
		u.sidebar.Add(btn)
	}

	u.btnUpload = widgets.NewButton("upload", "上传", widgets.ModeCustom)
	u.btnUpload.SetStyle(u.sidebarActionStyle())
	u.btnUpload.SetOnClick(func() {
		u.openUploadDialog()
	})

	u.btnSync = widgets.NewButton("sync", "同步", widgets.ModeCustom)
	u.btnSync.SetStyle(u.sidebarActionStyle())
	u.btnSync.SetOnClick(func() {
		u.openSyncDialog()
	})

	u.btnUpdate = widgets.NewButton("update", "更新", widgets.ModeCustom)
	u.btnUpdate.SetStyle(u.sidebarActionStyle())
	u.btnUpdate.SetOnClick(func() {
		u.openUpdateDialog()
	})

	u.btnAbout = widgets.NewButton("about", "关于", widgets.ModeCustom)
	u.btnAbout.SetStyle(u.sidebarActionStyle())
	u.btnAbout.SetOnClick(func() {
		u.openAboutDialog()
	})

	u.sidebar.AddAll(u.btnUpload, u.btnSync, u.btnUpdate, u.btnAbout)
}

func (u *nativeUI) refreshSidebar() {
	for _, key := range listOrder {
		btn := u.sideButtons[key]
		if btn == nil {
			continue
		}
		total := len(u.data[key])
		btn.SetText(fmt.Sprintf("%s  %d", listTitle[key], total))
		btn.SetStyle(u.sideButtonStyle(key == u.curKey))
	}
}

func (u *nativeUI) switchList(key string) {
	if u.curKey == key {
		return
	}
	u.curKey = key
	u.selectedRuleIndex = -1
	u.searchBox.SetText("")
	u.filter = ""
	u.refreshSidebar()
	u.refreshRuleList()
}

func (u *nativeUI) buildRulesCard() {
	u.ruleTitle = u.label("rule-title", "规则列表", 16, 700, u.col(23, 33, 61), core.DTEndEllipsis)
	u.ruleState = u.label("rule-state", "已加载", 12, 500, u.col(120, 132, 158), core.DTEndEllipsis)
	u.ruleNote = u.label("rule-note", "备注: -", 12, 400, u.col(103, 116, 145), dtWordBreak)

	u.searchBox = widgets.NewEditBox("search", widgets.ModeCustom)
	u.searchBox.SetPlaceholder("搜索...")
	u.searchBox.SetStyle(u.compactEditStyle())
	u.searchBox.SetOnChange(func(text string) {
		u.filter = strings.TrimSpace(text)
		u.refreshRuleList()
	})

	u.btnAdd = widgets.NewButton("add", "新增", widgets.ModeCustom)
	u.btnAdd.SetStyle(u.compactPrimaryButtonStyle())
	u.btnAdd.SetOnClick(func() {
		u.openAddDialog()
	})

	u.btnDel = widgets.NewButton("delete", "删除", widgets.ModeCustom)
	u.btnDel.SetStyle(u.compactOutlineDangerStyle())
	u.btnDel.SetEnabled(false)
	u.btnDel.SetOnClick(u.handleDelete)

	u.btnRuleFocus = widgets.NewButton("rules-focus", "放大", widgets.ModeCustom)
	u.btnRuleFocus.SetStyle(u.panelFocusButtonStyle())
	u.btnRuleFocus.SetKind(widgets.BtnLeft)
	u.btnRuleFocus.SetImage(u.enlargeImage)
	u.btnRuleFocus.SetOnClick(u.toggleRulesFocus)

	u.rulesList = widgets.NewListBox("rules")
	u.rulesList.SetStyle(u.ruleListStyle())
	u.rulesList.SetOnChange(func(index int, item widgets.ListItem) {
		if index < 0 || index >= len(u.ruleRows) {
			u.selectedRuleIndex = -1
			u.refreshRuleNote()
			return
		}
		u.selectedRuleIndex = u.ruleRows[index].Index
		u.refreshRuleNote()
		u.btnDel.SetEnabled(true)
	})

	u.rulesCard.AddAll(u.ruleTitle, u.ruleState, u.searchBox, u.btnAdd, u.btnDel, u.btnRuleFocus, u.rulesList, u.ruleNote)
}

func (u *nativeUI) refreshRuleList() {
	if u.rulesList == nil {
		return
	}
	all := u.data[u.curKey]
	filter := strings.ToLower(strings.TrimSpace(u.filter))
	rows := make([]ruleRow, 0, len(all))
	items := make([]widgets.ListItem, 0, len(all))
	selected := -1
	for idx, line := range all {
		note := strings.TrimSpace(u.notes[line])
		if filter != "" {
			lower := strings.ToLower(line)
			if !strings.Contains(lower, filter) && !strings.Contains(strings.ToLower(note), filter) {
				continue
			}
		}
		rows = append(rows, ruleRow{Index: idx, Text: line, Note: note})
		txt := line
		if note != "" {
			txt = line + "  |  " + note
		}
		items = append(items, widgets.ListItem{Value: strconv.Itoa(idx), Text: txt})
		if idx == u.selectedRuleIndex {
			selected = len(rows) - 1
		}
	}
	u.ruleRows = rows
	u.rulesList.SetItems(items)
	if selected >= 0 {
		u.rulesList.SetSelected(selected)
	} else {
		u.rulesList.ClearSelection()
		u.selectedRuleIndex = -1
	}

	u.refreshRuleHeader(len(all), len(rows), filter != "")
	u.refreshRuleNote()
	u.btnDel.SetEnabled(u.selectedRuleIndex >= 0 && u.panelFocus != panelFocusLogs)
}

func (u *nativeUI) refreshRuleHeader(total, filtered int, hasFilter bool) {
	if u.ruleTitle == nil || u.ruleState == nil {
		return
	}
	if u.panelFocus == panelFocusLogs {
		u.ruleTitle.SetText(fmt.Sprintf("%s  %d", listTitle[u.curKey], total))
		u.ruleState.SetText("")
		return
	}
	u.ruleTitle.SetText(fmt.Sprintf("规则列表 (%d)", total))
	if hasFilter {
		u.ruleState.SetText(fmt.Sprintf("筛选 %d 项", filtered))
	} else {
		u.ruleState.SetText("已加载")
	}
}

func (u *nativeUI) refreshRuleNote() {
	if u.ruleNote == nil {
		return
	}
	if u.selectedRuleIndex < 0 || u.selectedRuleIndex >= len(u.data[u.curKey]) {
		u.ruleNote.SetText("备注: -")
		return
	}
	val := u.data[u.curKey][u.selectedRuleIndex]
	note := strings.TrimSpace(u.notes[val])
	if note == "" {
		note = "无备注"
	}
	u.ruleNote.SetText("备注: " + note)
}

func (u *nativeUI) openAddDialog() {
	u.addHint.SetText("当前: " + listTitle[u.curKey])
	u.addInput.SetText("")
	u.showDialog(u.addDialog)
}

func (u *nativeUI) handleAdd() {
	txt := strings.TrimSpace(u.addInput.TextValue())
	if txt == "" {
		u.showMessage("内容为空。", true)
		return
	}
	if _, err := u.dat.addLn(u.curKey, txt); err != nil {
		u.showMessage("添加失败: "+err.Error(), true)
		return
	}
	u.hideDialogs()
	u.searchBox.SetText("")
	u.filter = ""
	u.reloadData()
	if len(u.data[u.curKey]) > 0 {
		u.selectedRuleIndex = len(u.data[u.curKey]) - 1
		u.refreshRuleList()
	}
	u.showMessage("已添加。", false)
}

func (u *nativeUI) handleDelete() {
	if u.selectedRuleIndex < 0 {
		u.showMessage("请先选择一项。", true)
		return
	}
	if !u.confirm("确定删除当前选中的规则吗？") {
		return
	}
	if _, err := u.dat.delLn(u.curKey, u.selectedRuleIndex); err != nil {
		u.showMessage("删除失败: "+err.Error(), true)
		return
	}
	u.selectedRuleIndex = -1
	u.reloadData()
	u.showMessage("已删除。", false)
}

func (u *nativeUI) buildLogsCard() {
	u.logTitle = u.label("log-title", "每日拦截记录", 16, 700, u.col(23, 33, 61), core.DTEndEllipsis)
	u.logInfo = u.label("log-info", "今日暂无记录", 12, 500, u.col(120, 132, 158), core.DTEndEllipsis)
	u.serviceLabel = u.label("service", "服务状态: 未知", 12, 500, u.col(22, 163, 74), core.DTEndEllipsis)
	u.serviceLabel.SetVisible(false)
	u.modeLabel = u.label("mode", "User Mode", 12, 500, u.col(103, 116, 145), core.DTEndEllipsis)

	u.logsList = widgets.NewListBox("logs")
	u.logsList.SetStyle(u.logListStyle())
	u.logsList.SetOnChange(func(index int, item widgets.ListItem) {
		if index < 0 || index >= len(u.logRows) {
			u.selectedLogIndex = -1
		} else {
			u.selectedLogIndex = index
		}
		u.refreshLogButtons()
	})
	u.logsList.SetOnActivate(func(index int, item widgets.ListItem) {
		u.openSelectedLog()
	})

	u.btnLogOpen = widgets.NewButton("log-open", "定位文件", widgets.ModeCustom)
	u.btnLogOpen.SetStyle(u.compactSoftButtonStyle())
	u.btnLogOpen.SetEnabled(false)
	u.btnLogOpen.SetOnClick(u.openSelectedLog)

	u.btnLogWhite = widgets.NewButton("log-white", "加入白名单", widgets.ModeCustom)
	u.btnLogWhite.SetStyle(u.compactSoftButtonStyle())
	u.btnLogWhite.SetEnabled(false)
	u.btnLogWhite.SetOnClick(u.addSelectedLogToWhitelist)

	u.btnLogFocus = widgets.NewButton("logs-focus", "放大", widgets.ModeCustom)
	u.btnLogFocus.SetStyle(u.panelFocusButtonStyle())
	u.btnLogFocus.SetKind(widgets.BtnLeft)
	u.btnLogFocus.SetImage(u.enlargeImage)
	u.btnLogFocus.SetOnClick(u.toggleLogsFocus)

	u.msgLabel = u.label("msg", "", 12, 500, u.col(120, 132, 158), dtWordBreak)

	u.logsCard.AddAll(
		u.logTitle,
		u.logInfo,
		u.btnLogFocus,
		u.logsList,
		u.btnLogOpen,
		u.btnLogWhite,
		u.modeLabel,
	)
	u.root.Add(u.msgLabel)
}

func (u *nativeUI) refreshLogList() {
	if u.logsList == nil {
		return
	}
	rows := make([]logRow, 0, len(u.logs))
	items := make([]widgets.ListItem, 0, len(u.logs))
	selected := -1
	for idx, raw := range u.logs {
		row, ok := u.parseLog(raw)
		if !ok {
			row = logRow{Text: raw}
		}
		rows = append(rows, row)
		items = append(items, widgets.ListItem{Value: strconv.Itoa(idx), Text: row.Text})
		if idx == u.selectedLogIndex {
			selected = idx
		}
	}
	u.logRows = rows
	u.logsList.SetItems(items)
	if selected >= 0 && selected < len(rows) {
		u.logsList.SetSelected(selected)
	} else {
		u.selectedLogIndex = -1
		u.logsList.ClearSelection()
	}
	if len(rows) == 0 {
		u.logInfo.SetText("今日暂无记录")
	} else {
		u.logInfo.SetText(fmt.Sprintf("今日记录 %d 条", len(rows)))
	}
	u.refreshPanelFocusChrome()
	u.refreshLogButtons()
	u.relayout()
}

func (u *nativeUI) refreshLogButtons() {
	if u.panelFocus == panelFocusRules || len(u.logRows) == 0 {
		u.btnLogOpen.SetEnabled(false)
		u.btnLogWhite.SetEnabled(false)
		return
	}
	row, ok := u.currentLogRow()
	u.btnLogOpen.SetEnabled(ok && strings.TrimSpace(row.Path) != "")
	u.btnLogWhite.SetEnabled(ok && (row.Kind == "sign" || row.Kind == "folder"))
}

func (u *nativeUI) toggleRulesFocus() {
	if u.panelFocus == panelFocusRules {
		u.panelFocus = panelFocusNone
	} else {
		u.panelFocus = panelFocusRules
	}
	u.refreshPanelFocusChrome()
	u.refreshLogButtons()
	u.relayout()
}

func (u *nativeUI) toggleLogsFocus() {
	if u.panelFocus == panelFocusLogs {
		u.panelFocus = panelFocusNone
	} else {
		u.panelFocus = panelFocusLogs
	}
	u.refreshPanelFocusChrome()
	u.refreshLogButtons()
	u.relayout()
}

func (u *nativeUI) relayout() {
	if u.app == nil {
		return
	}
	u.layout(u.app.ClientSize())
}

func (u *nativeUI) refreshPanelFocusChrome() {
	u.updatePanelFocusButton(u.btnRuleFocus, u.panelFocus == panelFocusRules)
	u.updatePanelFocusButton(u.btnLogFocus, u.panelFocus == panelFocusLogs)
	if u.btnLogFocus != nil {
		u.btnLogFocus.SetEnabled(u.panelFocus != panelFocusRules)
	}
	if u.ruleTitle != nil {
		total := len(u.data[u.curKey])
		u.refreshRuleHeader(total, len(u.ruleRows), strings.TrimSpace(u.filter) != "")
	}
}

func (u *nativeUI) updatePanelFocusButton(btn *widgets.Button, focused bool) {
	if btn == nil {
		return
	}
	if focused {
		btn.SetText("还原")
		btn.SetImage(u.restoreImage)
		return
	}
	btn.SetText("放大")
	btn.SetImage(u.enlargeImage)
}

func (u *nativeUI) openSelectedLog() {
	row, ok := u.currentLogRow()
	if !ok || strings.TrimSpace(row.Path) == "" {
		u.showMessage("当前记录没有可定位的路径。", true)
		return
	}
	if ok, err := openAndSelectPath(row.Path); err != nil {
		u.showMessage("打开失败: "+err.Error(), true)
	} else if !ok {
		u.showMessage("定位失败：文件可能已被删除。", true)
	}
}

func (u *nativeUI) addSelectedLogToWhitelist() {
	row, ok := u.currentLogRow()
	if !ok {
		u.showMessage("请先选择一条日志。", true)
		return
	}
	if row.Kind != "sign" && row.Kind != "folder" {
		u.showMessage("当前记录不支持加入白名单。", true)
		return
	}
	added, err := u.dat.addWhite(row.Kind, row.Value, row.Path)
	if err != nil {
		u.showMessage("加入白名单失败: "+err.Error(), true)
		return
	}
	u.reloadData()
	if added {
		u.showMessage("已加入白名单。", false)
	} else {
		u.showMessage("未添加，可能已经在白名单中。", false)
	}
}

func (u *nativeUI) parseLog(line string) (logRow, bool) {
	parts := strings.Split(line, "--")
	if len(parts) < 3 {
		return logRow{}, false
	}
	row := logRow{
		Time:  strings.TrimSpace(parts[0]),
		Kind:  strings.ToLower(strings.TrimSpace(parts[1])),
		Value: strings.TrimSpace(parts[2]),
	}
	if len(parts) == 4 {
		row.Path = strings.TrimSpace(parts[3])
	} else if len(parts) >= 5 {
		row.Path = strings.TrimSpace(strings.Join(parts[4:], "--"))
	}
	if row.Path == "" && len(parts) >= 4 {
		row.Path = strings.TrimSpace(parts[len(parts)-1])
	}

	switch row.Kind {
	case "sign":
		if containsFold(u.data["sign"], row.Value) {
			row.Status = "黑名单命中"
		} else if containsFold(u.data["signWhite"], row.Value) {
			row.Status = "白名单放行"
		} else {
			row.Status = "已拦截"
		}
	case "folder":
		if containsFold(u.data["folder"], row.Value) {
			row.Status = "黑名单命中"
		} else if containsFold(u.data["whitelist"], row.Value) {
			row.Status = "白名单放行"
		} else {
			row.Status = "已拦截"
		}
	default:
		row.Status = "已记录"
	}

	row.Note = strings.TrimSpace(u.notes[row.Value])
	row.Text = fmt.Sprintf("[%s] %s | %s", emptyAs(row.Time, "-"), baseName(row.Path), row.Status)
	if row.Note != "" {
		row.Text += " | " + row.Note
	}
	return row, true
}

func (u *nativeUI) currentLogRow() (logRow, bool) {
	if u.selectedLogIndex < 0 || u.selectedLogIndex >= len(u.logRows) {
		return logRow{}, false
	}
	return u.logRows[u.selectedLogIndex], true
}
