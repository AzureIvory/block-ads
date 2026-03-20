//go:build windows

package main

import (
	"block-ads-ui/utils"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AzureIvory/winui/core"
	"github.com/AzureIvory/winui/widgets"
)

const dtWordBreak uint32 = 0x00000010

var listOrder = []string{"sign", "folder", "whitelist", "signWhite"}

var listTitle = map[string]string{
	"sign":      "签名黑名单",
	"folder":    "目录黑名单",
	"whitelist": "目录白名单",
	"signWhite": "签名白名单",
}

var uploadOptions = []struct {
	Key   string
	Label string
}{
	{Key: "desktop", Label: "桌面快捷方式列表"},
	{Key: "process", Label: "进程名称列表"},
	{Key: "startup", Label: "启动项列表"},
	{Key: "startmenu", Label: "开始菜单列表"},
	{Key: "uninstall", Label: "卸载程序列表"},
}

type ruleRow struct {
	Index int
	Text  string
	Note  string
}

type logRow struct {
	Time   string
	Kind   string
	Value  string
	Path   string
	Note   string
	Status string
	Text   string
}

type nativeUI struct {
	app    *core.App
	scene  *widgets.Scene
	icon   *core.Icon
	dir    string
	exe    string
	codeEx string
	dat    *appDat

	stopCh   chan struct{}
	stopOnce sync.Once

	curKey            string
	filter            string
	selectedRuleIndex int
	selectedLogIndex  int
	syncPolicy        string

	status uiSta
	data   map[string][]string
	notes  map[string]string
	logs   []string

	ruleRows []ruleRow
	logRows  []logRow

	lastUpdate *UpdateInfo
	lastSync   *SyncInfo

	syncSelected  map[string]bool
	uploadChecked map[string]bool

	root         *widgets.Panel
	header       *widgets.Panel
	sidebar      *widgets.Panel
	rulesCard    *widgets.Panel
	logsCard     *widgets.Panel
	mask         *widgets.Panel
	activeDialog *widgets.Panel

	brandLabel   *widgets.Label
	msgLabel     *widgets.Label
	adminLabel   *widgets.Label
	runLabel     *widgets.Label
	serviceLabel *widgets.Label
	modeLabel    *widgets.Label
	ruleTitle    *widgets.Label
	ruleState    *widgets.Label
	ruleNote     *widgets.Label
	logTitle     *widgets.Label
	logInfo      *widgets.Label

	btnRun  *widgets.Button
	btnFake *widgets.Button
	btnHelp *widgets.Button
	btnGit  *widgets.Button

	btnUpload *widgets.Button
	btnSync   *widgets.Button
	btnUpdate *widgets.Button
	btnAbout  *widgets.Button

	btnAdd *widgets.Button
	btnDel *widgets.Button

	btnLogOpen  *widgets.Button
	btnLogWhite *widgets.Button

	chkBoot   *widgets.CheckBox
	searchBox *widgets.EditBox
	rulesList *widgets.ListBox
	logsList  *widgets.ListBox

	sideButtons map[string]*widgets.Button

	dialogs []*widgets.Panel

	addDialog  *widgets.Panel
	addTitle   *widgets.Label
	addHint    *widgets.Label
	addInput   *widgets.EditBox
	addCancel  *widgets.Button
	addConfirm *widgets.Button

	aboutDialog  *widgets.Panel
	aboutTitle   *widgets.Label
	aboutIcon    *widgets.Image
	aboutName    *widgets.Label
	aboutDesc    *widgets.Label
	aboutVersion *widgets.Label
	aboutGit     *widgets.Button
	aboutClose   *widgets.Button

	updateDialog  *widgets.Panel
	updateTitle   *widgets.Label
	updateVersion *widgets.Label
	updateDate    *widgets.Label
	updateNotes   *widgets.Label
	updateItems   *widgets.Label
	updateCheck   *widgets.Button
	updateGo      *widgets.Button
	updateClose   *widgets.Button

	syncDialog     *widgets.Panel
	syncTitle      *widgets.Label
	syncDesc       *widgets.Label
	syncDate       *widgets.Label
	syncNotes      *widgets.Label
	syncItemsPanel *widgets.Panel
	syncCheck      *widgets.Button
	syncGo         *widgets.Button
	syncClose      *widgets.Button
	syncRadioSel   *widgets.RadioButton
	syncRadioAll   *widgets.RadioButton
	syncRadioNever *widgets.RadioButton
	syncChecks     []*widgets.CheckBox

	uploadDialog *widgets.Panel
	uploadTitle  *widgets.Label
	uploadDesc   *widgets.Label
	uploadWarn   *widgets.Label
	uploadAll    *widgets.CheckBox
	uploadGo     *widgets.Button
	uploadClose  *widgets.Button
	uploadCancel *widgets.Button
	uploadChecks map[string]*widgets.CheckBox
}

func runNativeUI(dat *appDat, dir string) error {
	ui := &nativeUI{
		dir:               dir,
		exe:               filepath.Join(dir, exeName),
		codeEx:            filepath.Join(dir, codeExeName),
		dat:               dat,
		stopCh:            make(chan struct{}),
		curKey:            "sign",
		selectedRuleIndex: -1,
		selectedLogIndex:  -1,
		syncPolicy:        "auto_selected",
		syncSelected:      map[string]bool{},
		uploadChecked:     map[string]bool{},
		sideButtons:       map[string]*widgets.Button{},
		uploadChecks:      map[string]*widgets.CheckBox{},
	}
	for _, opt := range uploadOptions {
		ui.uploadChecked[opt.Key] = false
	}

	opts := core.Options{
		ClassName:      "BlockAdsWinUI",
		Title:          "名单管理",
		Width:          760,
		Height:         620,
		Style:          core.DefaultWindowStyle,
		ExStyle:        core.DefaultWindowExStyle,
		Cursor:         core.CursorArrow,
		Background:     ui.col(245, 248, 252),
		DoubleBuffered: true,
		RenderMode:     core.RenderModeAuto,
	}
	if ico := loadWinUIIcon(filepath.Join(dir, "icon.ico")); ico != nil {
		ui.icon = ico
		opts.Icon = ico
	}
	widgets.BindScene(&opts, widgets.SceneHooks{
		OnCreate:  ui.onCreate,
		OnResize:  ui.onResize,
		OnDestroy: ui.onDestroy,
	})

	app, err := core.NewApp(opts)
	if err != nil {
		return err
	}
	if err := app.Init(); err != nil {
		return err
	}
	app.Run()
	return nil
}

func (u *nativeUI) onCreate(app *core.App, scene *widgets.Scene) error {
	u.app = app
	u.scene = scene

	scene.SetTheme(u.theme())
	u.root = scene.Root()
	u.root.SetStyle(widgets.PanelStyle{
		Background:   u.col(245, 248, 252),
		CornerRadius: 0,
		BorderWidth:  0,
	})

	u.buildRoot()
	u.buildHeader()
	u.buildSidebar()
	u.buildRulesCard()
	u.buildLogsCard()
	u.buildDialogs()

	size := app.ClientSize()
	u.layout(size)
	u.reloadData()
	u.refreshStatus(u.currentStatus())
	u.startPolling()
	return nil
}

func (u *nativeUI) onResize(_ *core.App, _ *widgets.Scene, size core.Size) {
	u.layout(size)
}

func (u *nativeUI) onDestroy(_ *core.App, _ *widgets.Scene) {
	u.stopOnce.Do(func() {
		close(u.stopCh)
	})
	if u.icon != nil {
		_ = u.icon.Close()
		u.icon = nil
	}
}

func (u *nativeUI) buildRoot() {
	u.header = widgets.NewPanel("header")
	u.header.SetStyle(widgets.PanelStyle{
		Background:   u.col(250, 252, 255),
		BorderColor:  u.col(228, 235, 246),
		CornerRadius: 16,
		BorderWidth:  1,
	})

	u.sidebar = widgets.NewPanel("sidebar")
	u.sidebar.SetStyle(widgets.PanelStyle{
		Background:   u.col(250, 252, 255),
		BorderColor:  u.col(228, 235, 246),
		CornerRadius: 16,
		BorderWidth:  1,
	})

	u.rulesCard = widgets.NewPanel("rules-card")
	u.rulesCard.SetStyle(widgets.PanelStyle{
		Background:   u.col(255, 255, 255),
		BorderColor:  u.col(214, 224, 241),
		CornerRadius: 20,
		BorderWidth:  1,
	})

	u.logsCard = widgets.NewPanel("logs-card")
	u.logsCard.SetStyle(widgets.PanelStyle{
		Background:   u.col(252, 253, 255),
		BorderColor:  u.col(224, 231, 243),
		CornerRadius: 18,
		BorderWidth:  1,
	})

	u.mask = widgets.NewPanel("dialog-mask")
	u.mask.SetStyle(widgets.PanelStyle{
		Background:   u.col(239, 244, 251),
		CornerRadius: 0,
		BorderWidth:  0,
	})
	u.mask.SetVisible(false)
	u.mask.SetOnClick(func() {
		u.hideDialogs()
	})

	u.root.AddAll(u.header, u.sidebar, u.rulesCard, u.logsCard, u.mask)
}

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

	u.btnHelp = widgets.NewButton("help", "使用指南", widgets.ModeCustom)
	u.btnHelp.SetStyle(u.compactSoftButtonStyle())
	u.btnHelp.SetOnClick(u.handleHelp)

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
		u.btnHelp,
		u.btnGit,
	)
}

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

	u.rulesCard.AddAll(u.ruleTitle, u.ruleState, u.searchBox, u.btnAdd, u.btnDel, u.rulesList, u.ruleNote)
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

	u.msgLabel = u.label("msg", "", 12, 500, u.col(120, 132, 158), dtWordBreak)

	u.logsCard.AddAll(
		u.logTitle,
		u.logInfo,
		u.logsList,
		u.btnLogOpen,
		u.btnLogWhite,
		u.modeLabel,
	)
	u.root.Add(u.msgLabel)
}

func (u *nativeUI) buildDialogs() {
	u.buildAddDialog()
	u.buildAboutDialog()
	u.buildUpdateDialog()
	u.buildSyncDialog()
	u.buildUploadDialog()
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

func (u *nativeUI) buildAboutDialog() {
	u.aboutDialog = u.newDialog("about-dialog")
	u.aboutTitle = u.label("about-title", "关于", 20, 700, u.col(23, 33, 61), core.DTEndEllipsis)
	u.aboutIcon = widgets.NewImage("about-icon")
	u.aboutIcon.SetScaleMode(widgets.ImageScaleContain)
	if buf, err := os.ReadFile(filepath.Join(u.dir, "icon.png")); err == nil {
		_ = u.aboutIcon.LoadBytes(buf)
	}
	u.aboutName = u.label("about-name", "block-ads", 28, 700, u.col(47, 104, 243), core.DTCenter|core.DTEndEllipsis)
	u.aboutDesc = u.label("about-desc", "简单、高效的流氓软件拦截工具", 15, 400, u.col(76, 91, 119), core.DTCenter|dtWordBreak)
	u.aboutVersion = u.label("about-version", "Version -", 15, 500, u.col(103, 116, 145), core.DTCenter|core.DTEndEllipsis)
	u.aboutGit = widgets.NewButton("about-git", "GitHub", widgets.ModeCustom)
	u.aboutGit.SetStyle(u.softButtonStyle())
	u.aboutGit.SetOnClick(u.handleGit)
	u.aboutClose = widgets.NewButton("about-close", "关闭", widgets.ModeCustom)
	u.aboutClose.SetStyle(u.primaryButtonStyle())
	u.aboutClose.SetOnClick(func() {
		u.hideDialogs()
	})

	u.aboutDialog.AddAll(u.aboutTitle, u.aboutIcon, u.aboutName, u.aboutDesc, u.aboutVersion, u.aboutGit, u.aboutClose)
	u.registerDialog(u.aboutDialog)
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

	u.updateDialog.AddAll(
		u.updateTitle,
		u.updateVersion,
		u.updateDate,
		u.updateNotes,
		u.updateItems,
		u.updateCheck,
		u.updateGo,
		u.updateClose,
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

func (u *nativeUI) layout(size core.Size) {
	w := size.Width
	h := size.Height
	if w <= 0 || h <= 0 {
		return
	}

	m := u.dp(16)
	gap := u.dp(14)
	headerH := u.dp(60)
	sideW := u.dp(164)
	contentX := m + sideW + gap
	contentW := w - contentX - m
	topY := m + headerH + gap
	rulesH := u.dp(284)
	logsY := topY + rulesH + gap
	footerH := u.dp(28)
	logsH := h - logsY - m - footerH
	if logsH < u.dp(156) {
		logsH = u.dp(156)
	}

	u.header.SetBounds(core.Rect{X: m, Y: m, W: w - m*2, H: headerH})
	u.sidebar.SetBounds(core.Rect{X: m, Y: topY, W: sideW, H: h - topY - m})
	u.rulesCard.SetBounds(core.Rect{X: contentX, Y: topY, W: contentW, H: rulesH})
	u.logsCard.SetBounds(core.Rect{X: contentX, Y: logsY, W: contentW, H: logsH})
	u.mask.SetBounds(core.Rect{X: 0, Y: 0, W: w, H: h})

	u.brandLabel.SetBounds(core.Rect{X: m + u.dp(18), Y: m + u.dp(6), W: u.dp(138), H: u.dp(40)})
	u.btnRun.SetBounds(core.Rect{X: m + u.dp(160), Y: m + u.dp(10), W: u.dp(86), H: u.dp(36)})
	u.chkBoot.SetBounds(core.Rect{X: m + u.dp(258), Y: m + u.dp(12), W: u.dp(96), H: u.dp(30)})
	u.adminLabel.SetBounds(core.Rect{X: m + u.dp(346), Y: m + u.dp(14), W: u.dp(58), H: u.dp(24)})
	u.runLabel.SetBounds(core.Rect{X: m + u.dp(410), Y: m + u.dp(14), W: u.dp(58), H: u.dp(24)})
	u.btnFake.SetBounds(core.Rect{X: w - m - u.dp(252), Y: m + u.dp(10), W: u.dp(82), H: u.dp(36)})
	u.btnHelp.SetBounds(core.Rect{X: w - m - u.dp(164), Y: m + u.dp(10), W: u.dp(78), H: u.dp(36)})
	u.btnGit.SetBounds(core.Rect{X: w - m - u.dp(80), Y: m + u.dp(10), W: u.dp(74), H: u.dp(36)})

	sideX := m + u.dp(12)
	sideBtnW := sideW - u.dp(24)
	for i, key := range listOrder {
		y := topY + u.dp(14) + int32(i)*u.dp(48)
		u.sideButtons[key].SetBounds(core.Rect{X: sideX, Y: y, W: sideBtnW, H: u.dp(38)})
	}
	sideActionY := h - m - u.dp(158)
	u.btnUpload.SetBounds(core.Rect{X: sideX, Y: sideActionY, W: sideBtnW, H: u.dp(34)})
	u.btnSync.SetBounds(core.Rect{X: sideX, Y: sideActionY + u.dp(40), W: sideBtnW, H: u.dp(34)})
	u.btnUpdate.SetBounds(core.Rect{X: sideX, Y: sideActionY + u.dp(80), W: sideBtnW, H: u.dp(34)})
	u.btnAbout.SetBounds(core.Rect{X: sideX, Y: sideActionY + u.dp(120), W: sideBtnW, H: u.dp(34)})

	cardX := contentX + u.dp(14)
	cardW := contentW - u.dp(28)
	u.ruleTitle.SetBounds(core.Rect{X: cardX, Y: topY + u.dp(10), W: u.dp(236), H: u.dp(24)})
	u.ruleState.SetBounds(core.Rect{X: contentX + contentW - u.dp(98), Y: topY + u.dp(12), W: u.dp(70), H: u.dp(18)})
	u.searchBox.SetBounds(core.Rect{X: cardX, Y: topY + u.dp(40), W: cardW - u.dp(134), H: u.dp(30)})
	u.btnAdd.SetBounds(core.Rect{X: contentX + contentW - u.dp(120), Y: topY + u.dp(40), W: u.dp(54), H: u.dp(30)})
	u.btnDel.SetBounds(core.Rect{X: contentX + contentW - u.dp(60), Y: topY + u.dp(40), W: u.dp(46), H: u.dp(30)})
	u.rulesList.SetBounds(core.Rect{X: cardX, Y: topY + u.dp(80), W: cardW, H: rulesH - u.dp(112)})
	u.ruleNote.SetBounds(core.Rect{X: cardX, Y: topY + rulesH - u.dp(22), W: cardW, H: u.dp(16)})

	u.logTitle.SetBounds(core.Rect{X: cardX, Y: logsY + u.dp(10), W: u.dp(236), H: u.dp(22)})
	u.logInfo.SetBounds(core.Rect{X: contentX + contentW - u.dp(132), Y: logsY + u.dp(12), W: u.dp(104), H: u.dp(18)})
	u.logsList.SetBounds(core.Rect{X: cardX, Y: logsY + u.dp(40), W: cardW, H: logsH - u.dp(78)})
	u.btnLogOpen.SetBounds(core.Rect{X: cardX, Y: logsY + logsH - u.dp(38), W: u.dp(76), H: u.dp(28)})
	u.btnLogWhite.SetBounds(core.Rect{X: cardX + u.dp(84), Y: logsY + logsH - u.dp(38), W: u.dp(90), H: u.dp(28)})
	u.modeLabel.SetBounds(core.Rect{X: contentX + contentW - u.dp(108), Y: logsY + logsH - u.dp(16), W: u.dp(84), H: u.dp(16)})
	u.msgLabel.SetBounds(core.Rect{X: contentX, Y: h - m - footerH, W: contentW, H: footerH})

	u.layoutDialogs(w, h)
}

func (u *nativeUI) layoutDialogs(w, h int32) {
	center := func(dw, dh int32) core.Rect {
		return core.Rect{X: (w - dw) / 2, Y: (h - dh) / 2, W: dw, H: dh}
	}

	addRect := center(u.dp(430), u.dp(230))
	u.addDialog.SetBounds(addRect)
	u.addTitle.SetBounds(core.Rect{X: addRect.X + u.dp(24), Y: addRect.Y + u.dp(18), W: addRect.W - u.dp(48), H: u.dp(28)})
	u.addHint.SetBounds(core.Rect{X: addRect.X + u.dp(24), Y: addRect.Y + u.dp(62), W: addRect.W - u.dp(48), H: u.dp(38)})
	u.addInput.SetBounds(core.Rect{X: addRect.X + u.dp(24), Y: addRect.Y + u.dp(108), W: addRect.W - u.dp(48), H: u.dp(40)})
	u.addCancel.SetBounds(core.Rect{X: addRect.X + addRect.W - u.dp(184), Y: addRect.Y + addRect.H - u.dp(58), W: u.dp(74), H: u.dp(36)})
	u.addConfirm.SetBounds(core.Rect{X: addRect.X + addRect.W - u.dp(100), Y: addRect.Y + addRect.H - u.dp(58), W: u.dp(76), H: u.dp(36)})

	aboutRect := center(u.dp(500), u.dp(372))
	u.aboutDialog.SetBounds(aboutRect)
	u.aboutTitle.SetBounds(core.Rect{X: aboutRect.X + u.dp(24), Y: aboutRect.Y + u.dp(18), W: aboutRect.W - u.dp(48), H: u.dp(28)})
	u.aboutIcon.SetBounds(core.Rect{X: aboutRect.X + (aboutRect.W-u.dp(72))/2, Y: aboutRect.Y + u.dp(70), W: u.dp(72), H: u.dp(72)})
	u.aboutName.SetBounds(core.Rect{X: aboutRect.X + u.dp(40), Y: aboutRect.Y + u.dp(150), W: aboutRect.W - u.dp(80), H: u.dp(40)})
	u.aboutDesc.SetBounds(core.Rect{X: aboutRect.X + u.dp(80), Y: aboutRect.Y + u.dp(198), W: aboutRect.W - u.dp(160), H: u.dp(44)})
	u.aboutGit.SetBounds(core.Rect{X: aboutRect.X + (aboutRect.W-u.dp(104))/2, Y: aboutRect.Y + u.dp(252), W: u.dp(104), H: u.dp(38)})
	u.aboutVersion.SetBounds(core.Rect{X: aboutRect.X + u.dp(60), Y: aboutRect.Y + u.dp(300), W: aboutRect.W - u.dp(120), H: u.dp(24)})
	u.aboutClose.SetBounds(core.Rect{X: aboutRect.X + aboutRect.W - u.dp(100), Y: aboutRect.Y + aboutRect.H - u.dp(58), W: u.dp(76), H: u.dp(36)})

	updateRect := center(u.dp(640), u.dp(560))
	u.updateDialog.SetBounds(updateRect)
	u.updateTitle.SetBounds(core.Rect{X: updateRect.X + u.dp(24), Y: updateRect.Y + u.dp(18), W: u.dp(120), H: u.dp(28)})
	u.updateVersion.SetBounds(core.Rect{X: updateRect.X + u.dp(24), Y: updateRect.Y + u.dp(58), W: updateRect.W - u.dp(48), H: u.dp(24)})
	u.updateDate.SetBounds(core.Rect{X: updateRect.X + u.dp(24), Y: updateRect.Y + u.dp(92), W: updateRect.W - u.dp(48), H: u.dp(24)})
	u.updateNotes.SetBounds(core.Rect{X: updateRect.X + u.dp(24), Y: updateRect.Y + u.dp(126), W: updateRect.W - u.dp(48), H: u.dp(230)})
	u.updateItems.SetBounds(core.Rect{X: updateRect.X + u.dp(24), Y: updateRect.Y + u.dp(370), W: updateRect.W - u.dp(48), H: u.dp(110)})
	u.updateCheck.SetBounds(core.Rect{X: updateRect.X + updateRect.W - u.dp(286), Y: updateRect.Y + updateRect.H - u.dp(58), W: u.dp(90), H: u.dp(36)})
	u.updateGo.SetBounds(core.Rect{X: updateRect.X + updateRect.W - u.dp(188), Y: updateRect.Y + updateRect.H - u.dp(58), W: u.dp(76), H: u.dp(36)})
	u.updateClose.SetBounds(core.Rect{X: updateRect.X + updateRect.W - u.dp(100), Y: updateRect.Y + updateRect.H - u.dp(58), W: u.dp(76), H: u.dp(36)})

	syncRect := center(u.dp(650), u.dp(500))
	u.syncDialog.SetBounds(syncRect)
	u.syncTitle.SetBounds(core.Rect{X: syncRect.X + u.dp(24), Y: syncRect.Y + u.dp(18), W: u.dp(120), H: u.dp(28)})
	u.syncDesc.SetBounds(core.Rect{X: syncRect.X + u.dp(24), Y: syncRect.Y + u.dp(54), W: syncRect.W - u.dp(48), H: u.dp(22)})
	u.syncDate.SetBounds(core.Rect{X: syncRect.X + u.dp(24), Y: syncRect.Y + u.dp(86), W: syncRect.W - u.dp(48), H: u.dp(24)})
	u.syncNotes.SetBounds(core.Rect{X: syncRect.X + u.dp(24), Y: syncRect.Y + u.dp(116), W: syncRect.W - u.dp(48), H: u.dp(58)})
	u.syncItemsPanel.SetBounds(core.Rect{X: syncRect.X + u.dp(24), Y: syncRect.Y + u.dp(184), W: syncRect.W - u.dp(48), H: u.dp(146)})
	u.layoutSyncChecks()
	u.syncRadioSel.SetBounds(core.Rect{X: syncRect.X + u.dp(24), Y: syncRect.Y + u.dp(344), W: syncRect.W - u.dp(48), H: u.dp(28)})
	u.syncRadioAll.SetBounds(core.Rect{X: syncRect.X + u.dp(24), Y: syncRect.Y + u.dp(378), W: syncRect.W - u.dp(48), H: u.dp(28)})
	u.syncRadioNever.SetBounds(core.Rect{X: syncRect.X + u.dp(24), Y: syncRect.Y + u.dp(412), W: syncRect.W - u.dp(48), H: u.dp(28)})
	u.syncCheck.SetBounds(core.Rect{X: syncRect.X + syncRect.W - u.dp(286), Y: syncRect.Y + syncRect.H - u.dp(58), W: u.dp(90), H: u.dp(36)})
	u.syncGo.SetBounds(core.Rect{X: syncRect.X + syncRect.W - u.dp(188), Y: syncRect.Y + syncRect.H - u.dp(58), W: u.dp(76), H: u.dp(36)})
	u.syncClose.SetBounds(core.Rect{X: syncRect.X + syncRect.W - u.dp(100), Y: syncRect.Y + syncRect.H - u.dp(58), W: u.dp(76), H: u.dp(36)})

	uploadRect := center(u.dp(600), u.dp(470))
	u.uploadDialog.SetBounds(uploadRect)
	u.uploadTitle.SetBounds(core.Rect{X: uploadRect.X + u.dp(24), Y: uploadRect.Y + u.dp(18), W: u.dp(120), H: u.dp(28)})
	u.uploadClose.SetBounds(core.Rect{X: uploadRect.X + uploadRect.W - u.dp(100), Y: uploadRect.Y + u.dp(18), W: u.dp(76), H: u.dp(36)})
	u.uploadDesc.SetBounds(core.Rect{X: uploadRect.X + u.dp(24), Y: uploadRect.Y + u.dp(64), W: uploadRect.W - u.dp(120), H: u.dp(44)})
	u.uploadAll.SetBounds(core.Rect{X: uploadRect.X + uploadRect.W - u.dp(98), Y: uploadRect.Y + u.dp(70), W: u.dp(70), H: u.dp(28)})
	for idx, opt := range uploadOptions {
		y := uploadRect.Y + u.dp(122) + int32(idx)*u.dp(48)
		u.uploadChecks[opt.Key].SetBounds(core.Rect{X: uploadRect.X + u.dp(24), Y: y, W: uploadRect.W - u.dp(48), H: u.dp(34)})
	}
	u.uploadWarn.SetBounds(core.Rect{X: uploadRect.X + u.dp(24), Y: uploadRect.Y + uploadRect.H - u.dp(112), W: uploadRect.W - u.dp(48), H: u.dp(48)})
	u.uploadCancel.SetBounds(core.Rect{X: uploadRect.X + uploadRect.W - u.dp(188), Y: uploadRect.Y + uploadRect.H - u.dp(58), W: u.dp(76), H: u.dp(36)})
	u.uploadGo.SetBounds(core.Rect{X: uploadRect.X + uploadRect.W - u.dp(100), Y: uploadRect.Y + uploadRect.H - u.dp(58), W: u.dp(76), H: u.dp(36)})
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

func (u *nativeUI) startPolling() {
	go func() {
		tk := time.NewTicker(3 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-u.stopCh:
				return
			case <-tk.C:
				status := u.currentStatus()
				logs := u.dat.log()
				_ = u.app.Post(func() {
					u.logs = logs
					u.refreshStatus(status)
					u.refreshLogList()
				})
			}
		}
	}()
}

func (u *nativeUI) reloadData() {
	u.data = u.dat.all()
	u.notes = u.dat.note()
	u.logs = u.dat.log()
	u.refreshSidebar()
	u.refreshRuleList()
	u.refreshLogList()
	u.refreshAboutVersion()
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
		if len(rows) == 0 || !u.hasRuleIndex(u.selectedRuleIndex) {
			u.selectedRuleIndex = -1
		}
	}

	u.ruleTitle.SetText(fmt.Sprintf("规则列表 (%d)", len(all)))
	if filter != "" {
		u.ruleState.SetText(fmt.Sprintf("筛选 %d 项", len(rows)))
	} else {
		u.ruleState.SetText("已加载")
	}
	u.refreshRuleNote()
	u.btnDel.SetEnabled(u.selectedRuleIndex >= 0)
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
	u.refreshLogButtons()
}

func (u *nativeUI) refreshLogButtons() {
	row, ok := u.currentLogRow()
	u.btnLogOpen.SetEnabled(ok && strings.TrimSpace(row.Path) != "")
	u.btnLogWhite.SetEnabled(ok && (row.Kind == "sign" || row.Kind == "folder"))
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

func (u *nativeUI) refreshAboutVersion() {
	if u.aboutVersion == nil {
		return
	}
	ver := "-"
	if loc, err := u.dat.loadLocUM(); err == nil && strings.TrimSpace(loc.Ver) != "" {
		ver = strings.TrimSpace(loc.Ver)
	}
	u.aboutVersion.SetText("Version " + ver)
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

func (u *nativeUI) openAddDialog() {
	u.addHint.SetText("当前: " + listTitle[u.curKey])
	u.addInput.SetText("")
	u.showDialog(u.addDialog)
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

func (u *nativeUI) checkUpdateAsync(showMsg bool) {
	if showMsg {
		u.showMessage("检测更新中...", false)
	}
	go func() {
		info, err := u.dat.ChkUpd()
		_ = u.app.Post(func() {
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
	go func() {
		started, err := u.dat.DoUpdNative(func() {
			time.Sleep(250 * time.Millisecond)
			u.app.Close()
		})
		_ = u.app.Post(func() {
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
	go func() {
		info, err := u.dat.ChkSyn()
		_ = u.app.Post(func() {
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
	go func() {
		ok, err := u.dat.DoSyn(req)
		_ = u.app.Post(func() {
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

func (u *nativeUI) currentStatus() uiSta {
	return uiSta{
		Adm:  chkAdm(),
		Run:  chkRun(),
		Boot: hasBootKey(runName, u.exe) && hasBootKey(runNameCode, u.codeEx),
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

func (u *nativeUI) showMessage(text string, isErr bool) {
	if u.msgLabel == nil {
		return
	}
	u.msgLabel.SetText(text)
	if isErr {
		u.msgLabel.SetStyle(u.textStyle(13, 500, u.col(220, 38, 38), dtWordBreak))
		return
	}
	u.msgLabel.SetStyle(u.textStyle(13, 500, u.col(120, 132, 158), dtWordBreak))
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

func (u *nativeUI) theme() *widgets.Theme {
	theme := widgets.DefaultTheme()
	theme.BackgroundColor = u.col(245, 248, 252)
	theme.Text = u.textStyle(15, 400, u.col(23, 33, 61), core.DTVCenter|core.DTSingleLine)
	theme.Title = u.textStyle(20, 700, u.col(23, 33, 61), core.DTVCenter|core.DTSingleLine)
	theme.Button = u.softButtonStyle()
	theme.CheckBox = u.checkStyle()
	theme.RadioButton = u.radioStyle()
	theme.ListBox = u.ruleListStyle()
	theme.Edit = u.editStyle()
	return theme
}

func (u *nativeUI) label(id, text string, size, weight int32, color core.Color, format uint32) *widgets.Label {
	l := widgets.NewLabel(id, text)
	l.SetStyle(u.textStyle(size, weight, color, format))
	return l
}

func (u *nativeUI) textStyle(size, weight int32, color core.Color, format uint32) widgets.TextStyle {
	return widgets.TextStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei UI",
			SizeDP: size,
			Weight: weight,
		},
		Color:  color,
		Format: format,
	}
}

func (u *nativeUI) primaryButtonStyle() widgets.ButtonStyle {
	return widgets.ButtonStyle{
		Font:         widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 15, Weight: 700},
		TextColor:    u.col(255, 255, 255),
		DownText:     u.col(255, 255, 255),
		DisabledText: u.col(225, 232, 243),
		Background:   u.col(47, 104, 243),
		Hover:        u.col(38, 93, 228),
		Pressed:      u.col(31, 78, 200),
		Disabled:     u.col(160, 181, 235),
		Border:       u.col(47, 104, 243),
		CornerRadius: 12,
		PadDP:        12,
		TextInsetDP:  18,
		GapDP:        8,
	}
}

func (u *nativeUI) dangerButtonStyle() widgets.ButtonStyle {
	return widgets.ButtonStyle{
		Font:         widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 15, Weight: 700},
		TextColor:    u.col(255, 255, 255),
		DownText:     u.col(255, 255, 255),
		DisabledText: u.col(245, 210, 210),
		Background:   u.col(220, 38, 38),
		Hover:        u.col(200, 30, 30),
		Pressed:      u.col(165, 24, 24),
		Disabled:     u.col(240, 188, 188),
		Border:       u.col(220, 38, 38),
		CornerRadius: 12,
		PadDP:        12,
		TextInsetDP:  18,
		GapDP:        8,
	}
}

func (u *nativeUI) softButtonStyle() widgets.ButtonStyle {
	return widgets.ButtonStyle{
		Font:         widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 14, Weight: 600},
		TextColor:    u.col(41, 52, 77),
		DownText:     u.col(41, 52, 77),
		DisabledText: u.col(171, 183, 206),
		Background:   u.col(255, 255, 255),
		Hover:        u.col(242, 246, 253),
		Pressed:      u.col(232, 238, 250),
		Disabled:     u.col(245, 248, 252),
		Border:       u.col(220, 228, 242),
		CornerRadius: 12,
		PadDP:        12,
		TextInsetDP:  16,
		GapDP:        8,
	}
}

func (u *nativeUI) outlineDangerStyle() widgets.ButtonStyle {
	return widgets.ButtonStyle{
		Font:         widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 14, Weight: 600},
		TextColor:    u.col(220, 38, 38),
		DownText:     u.col(255, 255, 255),
		DisabledText: u.col(216, 158, 158),
		Background:   u.col(255, 255, 255),
		Hover:        u.col(254, 242, 242),
		Pressed:      u.col(220, 38, 38),
		Disabled:     u.col(252, 243, 243),
		Border:       u.col(252, 165, 165),
		CornerRadius: 12,
		PadDP:        12,
		TextInsetDP:  16,
		GapDP:        8,
	}
}

func (u *nativeUI) sideButtonStyle(active bool) widgets.ButtonStyle {
	if active {
		return widgets.ButtonStyle{
			Font:         widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 14, Weight: 700},
			TextColor:    u.col(47, 104, 243),
			DownText:     u.col(47, 104, 243),
			DisabledText: u.col(130, 156, 214),
			Background:   u.col(234, 242, 255),
			Hover:        u.col(229, 238, 255),
			Pressed:      u.col(219, 232, 255),
			Disabled:     u.col(240, 245, 255),
			Border:       u.col(156, 190, 252),
			CornerRadius: 13,
			PadDP:        10,
			TextInsetDP:  14,
			GapDP:        6,
		}
	}
	return widgets.ButtonStyle{
		Font:         widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 14, Weight: 600},
		TextColor:    u.col(31, 41, 55),
		DownText:     u.col(31, 41, 55),
		DisabledText: u.col(171, 183, 206),
		Background:   u.col(250, 252, 255),
		Hover:        u.col(243, 247, 254),
		Pressed:      u.col(236, 242, 252),
		Disabled:     u.col(245, 248, 252),
		Border:       u.col(226, 232, 243),
		CornerRadius: 13,
		PadDP:        10,
		TextInsetDP:  14,
		GapDP:        6,
	}
}

func (u *nativeUI) sidebarActionStyle() widgets.ButtonStyle {
	return widgets.ButtonStyle{
		Font:         widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 13, Weight: 600},
		TextColor:    u.col(33, 45, 76),
		DownText:     u.col(33, 45, 76),
		DisabledText: u.col(171, 183, 206),
		Background:   u.col(244, 247, 252),
		Hover:        u.col(236, 242, 252),
		Pressed:      u.col(228, 236, 250),
		Disabled:     u.col(247, 249, 252),
		Border:       u.col(228, 235, 246),
		CornerRadius: 10,
		PadDP:        8,
		TextInsetDP:  12,
		GapDP:        6,
	}
}

func (u *nativeUI) compactPrimaryButtonStyle() widgets.ButtonStyle {
	return widgets.ButtonStyle{
		Font:         widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 12, Weight: 700},
		TextColor:    u.col(255, 255, 255),
		DownText:     u.col(255, 255, 255),
		DisabledText: u.col(225, 232, 243),
		Background:   u.col(47, 104, 243),
		Hover:        u.col(38, 93, 228),
		Pressed:      u.col(31, 78, 200),
		Disabled:     u.col(160, 181, 235),
		Border:       u.col(47, 104, 243),
		CornerRadius: 9,
		PadDP:        7,
		TextInsetDP:  10,
		GapDP:        6,
	}
}

func (u *nativeUI) compactSoftButtonStyle() widgets.ButtonStyle {
	return widgets.ButtonStyle{
		Font:         widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 12, Weight: 600},
		TextColor:    u.col(41, 52, 77),
		DownText:     u.col(41, 52, 77),
		DisabledText: u.col(171, 183, 206),
		Background:   u.col(255, 255, 255),
		Hover:        u.col(242, 246, 253),
		Pressed:      u.col(232, 238, 250),
		Disabled:     u.col(245, 248, 252),
		Border:       u.col(220, 228, 242),
		CornerRadius: 9,
		PadDP:        7,
		TextInsetDP:  10,
		GapDP:        6,
	}
}

func (u *nativeUI) compactOutlineDangerStyle() widgets.ButtonStyle {
	return widgets.ButtonStyle{
		Font:         widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 12, Weight: 600},
		TextColor:    u.col(220, 38, 38),
		DownText:     u.col(255, 255, 255),
		DisabledText: u.col(216, 158, 158),
		Background:   u.col(255, 255, 255),
		Hover:        u.col(254, 242, 242),
		Pressed:      u.col(220, 38, 38),
		Disabled:     u.col(252, 243, 243),
		Border:       u.col(252, 165, 165),
		CornerRadius: 9,
		PadDP:        7,
		TextInsetDP:  10,
		GapDP:        6,
	}
}

func (u *nativeUI) iconDisplayButtonStyle() widgets.ButtonStyle {
	return widgets.ButtonStyle{
		Font:         widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 12, Weight: 400},
		TextColor:    u.col(255, 255, 255),
		DownText:     u.col(255, 255, 255),
		DisabledText: u.col(255, 255, 255),
		Background:   u.col(255, 255, 255),
		Hover:        u.col(255, 255, 255),
		Pressed:      u.col(255, 255, 255),
		Disabled:     u.col(255, 255, 255),
		Border:       u.col(255, 255, 255),
		CornerRadius: 0,
		IconSizeDP:   72,
		TextInsetDP:  0,
		GapDP:        0,
		PadDP:        0,
	}
}

func (u *nativeUI) checkStyle() widgets.ChoiceStyle {
	return widgets.ChoiceStyle{
		Font:            widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 14, Weight: 500},
		TextColor:       u.col(44, 56, 82),
		DisabledText:    u.col(148, 163, 184),
		Background:      u.col(255, 255, 255),
		BorderColor:     u.col(203, 213, 225),
		HoverBorder:     u.col(96, 165, 250),
		FocusBorder:     u.col(47, 104, 243),
		IndicatorColor:  u.col(47, 104, 243),
		CheckColor:      u.col(255, 255, 255),
		HoverBackground: u.col(243, 247, 254),
		DisabledBg:      u.col(245, 247, 250),
		DisabledBorder:  u.col(212, 218, 228),
		CornerRadius:    6,
		IndicatorStyle:  widgets.ChoiceIndicatorDot,
		IndicatorSizeDP: 18,
		IndicatorGapDP:  10,
	}
}

func (u *nativeUI) radioStyle() widgets.ChoiceStyle {
	return widgets.ChoiceStyle{
		Font:            widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 14, Weight: 500},
		TextColor:       u.col(44, 56, 82),
		DisabledText:    u.col(148, 163, 184),
		Background:      u.col(255, 255, 255),
		BorderColor:     u.col(203, 213, 225),
		HoverBorder:     u.col(96, 165, 250),
		FocusBorder:     u.col(47, 104, 243),
		IndicatorColor:  u.col(47, 104, 243),
		CheckColor:      u.col(255, 255, 255),
		HoverBackground: u.col(243, 247, 254),
		DisabledBg:      u.col(245, 247, 250),
		DisabledBorder:  u.col(212, 218, 228),
		CornerRadius:    9,
		IndicatorStyle:  widgets.ChoiceIndicatorDot,
		IndicatorSizeDP: 18,
		IndicatorGapDP:  10,
	}
}

func (u *nativeUI) ruleListStyle() widgets.ListStyle {
	return widgets.ListStyle{
		Font:              widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 13, Weight: 500},
		TextColor:         u.col(31, 41, 55),
		DisabledText:      u.col(148, 163, 184),
		Background:        u.col(255, 255, 255),
		BorderColor:       u.col(223, 230, 243),
		HoverBorder:       u.col(96, 165, 250),
		FocusBorder:       u.col(47, 104, 243),
		ItemHoverColor:    u.col(242, 247, 255),
		ItemSelectedColor: u.col(47, 104, 243),
		ItemTextColor:     u.col(255, 255, 255),
		ItemHeightDP:      30,
		PaddingDP:         8,
		CornerRadius:      12,
	}
}

func (u *nativeUI) logListStyle() widgets.ListStyle {
	return widgets.ListStyle{
		Font:              widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 13, Weight: 500},
		TextColor:         u.col(41, 52, 77),
		DisabledText:      u.col(148, 163, 184),
		Background:        u.col(255, 255, 255),
		BorderColor:       u.col(223, 230, 243),
		HoverBorder:       u.col(96, 165, 250),
		FocusBorder:       u.col(47, 104, 243),
		ItemHoverColor:    u.col(244, 247, 252),
		ItemSelectedColor: u.col(234, 242, 255),
		ItemTextColor:     u.col(47, 104, 243),
		ItemHeightDP:      28,
		PaddingDP:         8,
		CornerRadius:      12,
	}
}

func (u *nativeUI) editStyle() widgets.EditStyle {
	return widgets.EditStyle{
		Font:             widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 14, Weight: 500},
		TextColor:        u.col(31, 41, 55),
		PlaceholderColor: u.col(148, 163, 184),
		Background:       u.col(255, 255, 255),
		BorderColor:      u.col(223, 230, 243),
		HoverBorder:      u.col(96, 165, 250),
		FocusBorder:      u.col(47, 104, 243),
		DisabledText:     u.col(148, 163, 184),
		DisabledBg:       u.col(245, 247, 250),
		CaretColor:       u.col(47, 104, 243),
		PaddingDP:        12,
		CornerRadius:     12,
	}
}

func (u *nativeUI) compactEditStyle() widgets.EditStyle {
	return widgets.EditStyle{
		Font:             widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 12, Weight: 500},
		TextColor:        u.col(31, 41, 55),
		PlaceholderColor: u.col(148, 163, 184),
		Background:       u.col(255, 255, 255),
		BorderColor:      u.col(223, 230, 243),
		HoverBorder:      u.col(96, 165, 250),
		FocusBorder:      u.col(47, 104, 243),
		DisabledText:     u.col(148, 163, 184),
		DisabledBg:       u.col(245, 247, 250),
		CaretColor:       u.col(47, 104, 243),
		PaddingDP:        8,
		CornerRadius:     9,
	}
}

func (u *nativeUI) col(r, g, b byte) core.Color {
	return core.RGB(r, g, b)
}

func (u *nativeUI) dp(v int32) int32 {
	if u.app == nil {
		return v
	}
	return u.app.DP(v)
}

func (u *nativeUI) hasRuleIndex(idx int) bool {
	return idx >= 0 && idx < len(u.data[u.curKey])
}

func loadWinUIIcon(path string) *core.Icon {
	return loadWinUIIconSized(path, 48)
}

func loadWinUIIconSized(path string, want int32) *core.Icon {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	icon, err := core.LoadIconFromICO(buf, want)
	if err != nil {
		return nil
	}
	return icon
}

func clearPanelChildren(panel *widgets.Panel) {
	if panel == nil {
		return
	}
	for _, child := range panel.Children() {
		panel.Remove(child.ID())
	}
}

func containsFold(items []string, target string) bool {
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item), strings.TrimSpace(target)) {
			return true
		}
	}
	return false
}

func emptyAs(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func ternary(cond bool, yes, no string) string {
	if cond {
		return yes
	}
	return no
}

func baseName(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "-"
	}
	parts := strings.FieldsFunc(path, func(r rune) bool {
		return r == '\\' || r == '/'
	})
	if len(parts) == 0 {
		return path
	}
	return parts[len(parts)-1]
}

func openAndSelectPath(path string) (bool, error) {
	path = strings.Trim(strings.TrimSpace(path), `"`)
	if path == "" {
		return false, fmt.Errorf("empty path")
	}
	path = filepath.Clean(filepath.FromSlash(path))
	if _, err := os.Stat(path); err != nil {
		dir := filepath.Dir(path)
		if _, derr := os.Stat(dir); derr == nil {
			_ = exec.Command("explorer.exe", dir).Start()
			return false, nil
		}
		return false, err
	}
	cmd := exec.Command("explorer.exe", "/select,", path)
	if err := cmd.Start(); err != nil {
		return false, err
	}
	return true, nil
}
