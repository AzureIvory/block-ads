//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/AzureIvory/winui/core"
	"github.com/AzureIvory/winui/widgets"
)

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

	u.buildAll()

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
	if u.enlargeImage != nil {
		_ = u.enlargeImage.Close()
		u.enlargeImage = nil
	}
	if u.restoreImage != nil {
		_ = u.restoreImage.Close()
		u.restoreImage = nil
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

func (u *nativeUI) currentStatus() uiSta {
	return uiSta{
		Adm:      chkAdm(),
		Run:      chkRun(),
		Boot:     hasBootKey(runName, u.exe),
		CodeBoot: hasBootKey(runNameCode, u.codeEx),
	}
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

func loadWinUIIcon() *core.Icon {
	return loadWinUIIconSized(assetIconICO, 48)
}

func loadWinUIIconSized(buf []byte, want int32) *core.Icon {
	if len(buf) == 0 {
		return nil
	}
	icon, err := core.LoadIconFromICO(buf, want)
	if err != nil {
		return nil
	}
	return icon
}

func loadUIAssetImage(dir, name string) *core.Image {
	img, err := core.LoadImageBytes(assetImage(name))
	if err != nil {
		return nil
	}
	return img
}

// newWaitAnim 创建网络等待动画，加载失败返回 nil。
func (u *nativeUI) newWaitAnim() *widgets.AnimatedImage {
	anim := widgets.NewAnimatedImage("wait-anim")
	if err := anim.LoadGIF(assetWaitGIF); err != nil {
		return nil
	}
	anim.SetVisible(false)
	return anim
}

// setWaiting 在指定对话框内显示/隐藏等待动画。
func (u *nativeUI) setWaiting(anim *widgets.AnimatedImage, rect core.Rect, on bool) {
	if anim == nil {
		return
	}
	anim.SetBounds(rect)
	anim.SetVisible(on)
	anim.SetPlaying(on)
}

// setUpdateWaiting 切换更新对话框的等待动画。
func (u *nativeUI) setUpdateWaiting(on bool) {
	if u.updateWait == nil {
		return
	}
	r := u.updateWait.Bounds()
	if r.Empty() {
		r = core.Rect{X: u.dp(8), Y: u.dp(8), W: u.dp(120), H: u.dp(120)}
	}
	u.setWaiting(u.updateWait, r, on)
}

// setSyncWaiting 切换同步对话框的等待动画。
func (u *nativeUI) setSyncWaiting(on bool) {
	if u.syncWait == nil {
		return
	}
	r := u.syncWait.Bounds()
	if r.Empty() {
		r = core.Rect{X: u.dp(8), Y: u.dp(8), W: u.dp(120), H: u.dp(120)}
	}
	u.setWaiting(u.syncWait, r, on)
}

func clearPanelChildren(panel *widgets.Panel) {
	if panel == nil {
		return
	}
	for _, child := range panel.Children() {
		panel.Remove(child.ID())
	}
}

// uiMdl 封装界面共享状态。
type uiMdl struct {
	ui *nativeUI
}

// headCtl 管理顶部区域。
type headCtl struct {
	ui  *nativeUI
	pan *widgets.Panel
}

// sideCtl 管理左侧区域。
type sideCtl struct {
	ui  *nativeUI
	pan *widgets.Panel
}

// ruleCtl 管理规则区域。
type ruleCtl struct {
	ui  *nativeUI
	pan *widgets.Panel
}

// logCtl 管理日志区域。
type logCtl struct {
	ui  *nativeUI
	pan *widgets.Panel
}

// addDlg 映射新增弹窗。
type addDlg struct {
	pan *widgets.Panel
}

// abtDlg 映射关于弹窗。
type abtDlg struct {
	pan *widgets.Panel
	ver *widgets.Label
}

// fakeDlg 映射伪装弹窗。
type fakeDlg struct {
	pan *widgets.Panel
	msg *widgets.Label
}

// updDlg 映射更新弹窗。
type updDlg struct {
	pan *widgets.Panel
}

// synDlg 映射同步弹窗。
type synDlg struct {
	pan *widgets.Panel
}

// upDlg 映射上传弹窗。
type upDlg struct {
	pan *widgets.Panel
}

// dlgCtl 管理全部弹窗。
type dlgCtl struct {
	ui   *nativeUI
	add  addDlg
	abt  abtDlg
	fake fakeDlg
	upd  updDlg
	syn  synDlg
	up   upDlg
}

// newUI 创建界面主控。
func newUI(dat *appDat, dir string) *nativeUI {
	u := &nativeUI{
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
		u.uploadChecked[opt.Key] = false
	}
	u.mdl = &uiMdl{ui: u}
	u.head = &headCtl{ui: u}
	u.side = &sideCtl{ui: u}
	u.rule = &ruleCtl{ui: u}
	u.log = &logCtl{ui: u}
	u.dlg = &dlgCtl{ui: u}
	return u
}

// buildAll 组装全部区域。
func (u *nativeUI) buildAll() {
	u.enlargeImage = loadUIAssetImage(u.dir, "Enlarge.png")
	u.restoreImage = loadUIAssetImage(u.dir, "Minimize.png")
	u.fakeImage = loadUIAssetImage(u.dir, "Guard.png")
	u.gitImage = loadUIAssetImage(u.dir, "GitHub.png")
	u.startImage = loadUIAssetImage(u.dir, "start.png")
	u.enableImage = loadUIAssetImage(u.dir, "enable.png")
	u.disabledImage = loadUIAssetImage(u.dir, "disabled.png")
	u.buildRoot()
	u.buildHeader()
	u.buildSidebar()
	u.buildRulesCard()
	u.buildLogsCard()
	u.buildDialogs()
	u.linkCtl()
	u.refreshPanelFocusChrome()
}

// linkCtl 把旧控件绑定到新控制器。
func (u *nativeUI) linkCtl() {
	u.head.pan = u.header
	u.side.pan = u.sidebar
	u.rule.pan = u.rulesCard
	u.log.pan = u.logsCard

	u.dlg.add.pan = u.addDialog
	u.dlg.abt.pan = u.aboutDialog
	u.dlg.abt.ver = u.aboutVersion
	u.dlg.fake.pan = u.fakeConfirmDialog
	u.dlg.fake.msg = u.fakeConfirmMessage
	u.dlg.upd.pan = u.updateDialog
	u.dlg.syn.pan = u.syncDialog
	u.dlg.up.pan = u.uploadDialog
}

// syncAbt 刷新关于版本。
func (d *dlgCtl) syncAbt() {
	d.ui.refreshAboutVersion()
}

// containsFold 忽略大小写比较切片内容。
func containsFold(items []string, target string) bool {
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item), strings.TrimSpace(target)) {
			return true
		}
	}
	return false
}

// emptyAs 返回非空值或回退值。
func emptyAs(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

// ternary 返回简单二选一结果。
func ternary(cond bool, yes, no string) string {
	if cond {
		return yes
	}
	return no
}

// baseName 提取路径末级名称。
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

// openAndSelectPath 打开并尝试定位文件。
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

	footerH := u.dp(28)

	contentBottom := h - m - footerH
	if contentBottom-topY < u.dp(480) {
		contentBottom = topY + u.dp(480)
	}
	contentPlan := planContentLayout(topY, contentBottom, gap, u.dp(44), u.dp(152), len(u.logRows), u.panelFocus)
	rulesH := contentPlan.RulesH
	logsY := contentPlan.LogsY
	logsH := contentPlan.LogsH

	u.header.SetBounds(core.Rect{X: m, Y: m, W: w - m*2, H: headerH})
	u.sidebar.SetBounds(core.Rect{X: m, Y: topY, W: sideW, H: h - topY - m})
	u.rulesCard.SetBounds(core.Rect{X: contentX, Y: topY, W: contentW, H: rulesH})
	u.logsCard.SetVisible(contentPlan.ShowLogs)
	if contentPlan.ShowLogs {
		u.logsCard.SetBounds(core.Rect{X: contentX, Y: logsY, W: contentW, H: logsH})
	}
	u.mask.SetBounds(core.Rect{X: 0, Y: 0, W: w, H: h})

	rightGitX := w - m - u.dp(120)
	rightFakeX := rightGitX - u.dp(138)

	u.btnGit.SetBounds(core.Rect{X: rightGitX, Y: m + u.dp(8), W: u.dp(116), H: u.dp(40)})
	u.btnFake.SetBounds(core.Rect{X: rightFakeX, Y: m + u.dp(8), W: u.dp(130), H: u.dp(40)})

	leftX := m + u.dp(18)
	u.brandLabel.SetBounds(core.Rect{X: leftX, Y: m + u.dp(6), W: u.dp(120), H: u.dp(40)})
	leftX += u.dp(128)

	u.btnRun.SetBounds(core.Rect{X: leftX, Y: m + u.dp(10), W: u.dp(82), H: u.dp(36)})
	leftX += u.dp(90)

	u.chkBoot.SetBounds(core.Rect{X: leftX, Y: m + u.dp(12), W: u.dp(106), H: u.dp(30)})
	leftX += u.dp(112)

	u.chkCode.SetBounds(core.Rect{X: leftX, Y: m + u.dp(12), W: u.dp(106), H: u.dp(30)})
	leftX += u.dp(112)

	if leftX+u.dp(120) < rightFakeX-u.dp(8) {
		u.adminLabel.SetBounds(core.Rect{X: leftX, Y: m + u.dp(14), W: u.dp(54), H: u.dp(24)})
		u.runLabel.SetBounds(core.Rect{X: leftX + u.dp(60), Y: m + u.dp(14), W: u.dp(54), H: u.dp(24)})
		u.adminLabel.SetVisible(true)
		u.runLabel.SetVisible(true)
	} else {
		u.adminLabel.SetVisible(false)
		u.runLabel.SetVisible(false)
	}

	sideX := m + u.dp(12)
	sideBtnW := sideW - u.dp(24)

	for i, key := range listOrder {
		y := topY + u.dp(12) + int32(i)*u.dp(42)
		u.sideButtons[key].SetBounds(core.Rect{X: sideX, Y: y, W: sideBtnW, H: u.dp(34)})
	}

	sideActionY := h - m - u.dp(146)
	u.btnUpload.SetBounds(core.Rect{X: sideX, Y: sideActionY, W: sideBtnW, H: u.dp(32)})
	u.btnSync.SetBounds(core.Rect{X: sideX, Y: sideActionY + u.dp(36), W: sideBtnW, H: u.dp(32)})
	u.btnUpdate.SetBounds(core.Rect{X: sideX, Y: sideActionY + u.dp(72), W: sideBtnW, H: u.dp(32)})
	u.btnAbout.SetBounds(core.Rect{X: sideX, Y: sideActionY + u.dp(108), W: sideBtnW, H: u.dp(32)})

	cardX := contentX + u.dp(14)
	cardW := contentW - u.dp(28)
	u.ruleTitle.SetBounds(core.Rect{X: cardX, Y: topY + u.dp(10), W: cardW - u.dp(168), H: u.dp(24)})
	u.btnRuleFocus.SetBounds(core.Rect{X: contentX + contentW - u.dp(82), Y: topY + u.dp(9), W: u.dp(68), H: u.dp(28)})
	u.ruleState.SetBounds(core.Rect{X: contentX + contentW - u.dp(160), Y: topY + u.dp(12), W: u.dp(68), H: u.dp(18)})
	u.searchBox.SetBounds(core.Rect{X: cardX, Y: topY + u.dp(40), W: cardW - u.dp(292), H: u.dp(30)})
	u.btnEnabled.SetBounds(core.Rect{X: contentX + contentW - u.dp(280), Y: topY + u.dp(40), W: u.dp(96), H: u.dp(30)})
	u.btnDisabled.SetBounds(core.Rect{X: contentX + contentW - u.dp(176), Y: topY + u.dp(40), W: u.dp(96), H: u.dp(30)})
	u.btnAdd.SetBounds(core.Rect{X: contentX + contentW - u.dp(72), Y: topY + u.dp(40), W: u.dp(58), H: u.dp(30)})
	ruleListH := rulesH - u.dp(116)
	if ruleListH < u.dp(40) {
		ruleListH = u.dp(40)
	}
	u.rulesList.SetBounds(core.Rect{X: cardX, Y: topY + u.dp(80), W: cardW, H: ruleListH})
	u.ruleNote.SetBounds(core.Rect{X: cardX, Y: topY + rulesH - u.dp(28), W: cardW, H: u.dp(22)})

	u.ruleState.SetVisible(contentPlan.ShowRuleBody)
	u.searchBox.SetVisible(contentPlan.ShowRuleBody)
	u.btnAdd.SetVisible(contentPlan.ShowRuleBody)
	u.btnEnabled.SetVisible(contentPlan.ShowRuleBody)
	u.btnDisabled.SetVisible(contentPlan.ShowRuleBody)
	u.btnRuleFocus.SetVisible(contentPlan.ShowRuleBody)
	u.rulesList.SetVisible(contentPlan.ShowRuleBody)
	u.ruleNote.SetVisible(contentPlan.ShowRuleBody)

	logPad := u.dp(14)
	logHeaderH := u.dp(28)
	logFooterH := u.dp(40)

	logCardX := contentX
	logCardY := logsY
	logCardW := contentW
	logCardH := logsH

	logInnerX := logCardX + logPad
	logInnerW := logCardW - logPad*2

	u.logTitle.SetBounds(core.Rect{
		X: logInnerX,
		Y: logCardY + u.dp(10),
		W: logInnerW - u.dp(220),
		H: u.dp(22),
	})

	logFocusX := logCardX + logCardW - u.dp(82)
	u.btnLogFocus.SetBounds(core.Rect{
		X: logFocusX,
		Y: logCardY + u.dp(6),
		W: u.dp(68),
		H: u.dp(28),
	})

	u.logInfo.SetBounds(core.Rect{
		X: logFocusX - u.dp(134),
		Y: logCardY + u.dp(12),
		W: u.dp(122),
		H: u.dp(18),
	})

	listY := logCardY + logHeaderH + u.dp(8)
	listH := logCardH - logHeaderH - logFooterH - u.dp(12)
	if listH < u.dp(80) {
		listH = u.dp(80)
	}

	u.logsList.SetBounds(core.Rect{
		X: logInnerX,
		Y: listY,
		W: logInnerW,
		H: listH,
	})

	footerY := logCardY + logCardH - logFooterH + u.dp(6)

	u.btnLogOpen.SetBounds(core.Rect{
		X: logInnerX,
		Y: footerY,
		W: u.dp(76),
		H: u.dp(28),
	})

	u.btnLogWhite.SetBounds(core.Rect{
		X: logInnerX + u.dp(84),
		Y: footerY,
		W: u.dp(90),
		H: u.dp(28),
	})

	u.modeLabel.SetBounds(core.Rect{
		X: logCardX + logCardW - u.dp(112),
		Y: footerY + u.dp(6),
		W: u.dp(88),
		H: u.dp(18),
	})

	u.logTitle.SetVisible(contentPlan.ShowLogs)
	u.logInfo.SetVisible(contentPlan.ShowLogs)
	u.btnLogFocus.SetVisible(contentPlan.ShowLogs)
	u.logsList.SetVisible(contentPlan.ShowLogBody)
	u.logsList.SetEnabled(contentPlan.ShowLogBody)
	u.btnLogOpen.SetVisible(contentPlan.ShowLogBody)
	u.btnLogWhite.SetVisible(contentPlan.ShowLogBody)
	u.modeLabel.SetVisible(contentPlan.ShowLogBody)

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

	alertRect := center(u.dp(420), u.dp(200))
	u.alertDialog.SetBounds(alertRect)
	u.alertLabel.SetBounds(core.Rect{X: alertRect.X + u.dp(24), Y: alertRect.Y + u.dp(24), W: alertRect.W - u.dp(48), H: alertRect.H - u.dp(110)})
	u.alertClose.SetBounds(core.Rect{X: alertRect.X + (alertRect.W-u.dp(76))/2, Y: alertRect.Y + alertRect.H - u.dp(58), W: u.dp(76), H: u.dp(36)})


	aboutRect := center(u.dp(500), u.dp(372))
	u.aboutDialog.SetBounds(aboutRect)
	u.aboutTitle.SetBounds(core.Rect{X: aboutRect.X + u.dp(24), Y: aboutRect.Y + u.dp(18), W: aboutRect.W - u.dp(48), H: u.dp(28)})
	u.aboutIcon.SetBounds(core.Rect{X: aboutRect.X + (aboutRect.W-u.dp(72))/2, Y: aboutRect.Y + u.dp(70), W: u.dp(72), H: u.dp(72)})
	u.aboutName.SetBounds(core.Rect{X: aboutRect.X + u.dp(40), Y: aboutRect.Y + u.dp(150), W: aboutRect.W - u.dp(80), H: u.dp(40)})
	u.aboutDesc.SetBounds(core.Rect{X: aboutRect.X + u.dp(80), Y: aboutRect.Y + u.dp(198), W: aboutRect.W - u.dp(160), H: u.dp(44)})
	u.aboutGit.SetBounds(core.Rect{X: aboutRect.X + (aboutRect.W-u.dp(104))/2, Y: aboutRect.Y + u.dp(252), W: u.dp(104), H: u.dp(38)})
	u.aboutVersion.SetBounds(core.Rect{X: aboutRect.X + u.dp(60), Y: aboutRect.Y + u.dp(300), W: aboutRect.W - u.dp(120), H: u.dp(24)})
	u.aboutClose.SetBounds(core.Rect{X: aboutRect.X + aboutRect.W - u.dp(100), Y: aboutRect.Y + aboutRect.H - u.dp(58), W: u.dp(76), H: u.dp(36)})

	fakeRect := center(u.dp(660), u.dp(390))
	u.fakeConfirmDialog.SetBounds(fakeRect)
	u.fakeConfirmTitle.SetBounds(core.Rect{X: fakeRect.X + u.dp(24), Y: fakeRect.Y + u.dp(18), W: fakeRect.W - u.dp(48), H: u.dp(28)})
	u.fakeConfirmMessage.SetBounds(core.Rect{X: fakeRect.X + u.dp(24), Y: fakeRect.Y + u.dp(60), W: fakeRect.W - u.dp(48), H: u.dp(244)})
	u.fakeConfirmCancel.SetBounds(core.Rect{X: fakeRect.X + fakeRect.W - u.dp(188), Y: fakeRect.Y + fakeRect.H - u.dp(58), W: u.dp(76), H: u.dp(36)})
	u.fakeConfirmContinue.SetBounds(core.Rect{X: fakeRect.X + fakeRect.W - u.dp(100), Y: fakeRect.Y + fakeRect.H - u.dp(58), W: u.dp(76), H: u.dp(36)})

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
	u.setWaiting(u.updateWait, core.Rect{X: updateRect.X + (updateRect.W-u.dp(120))/2, Y: updateRect.Y + u.dp(160), W: u.dp(120), H: u.dp(120)}, u.updateWait != nil && u.updateWait.Visible())

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
	u.setWaiting(u.syncWait, core.Rect{X: syncRect.X + (syncRect.W-u.dp(120))/2, Y: syncRect.Y + u.dp(150), W: u.dp(120), H: u.dp(120)}, u.syncWait != nil && u.syncWait.Visible())

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
