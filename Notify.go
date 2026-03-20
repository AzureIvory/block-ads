//go:build windows

package main

import (
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/AzureIvory/winui/core"
	"github.com/AzureIvory/winui/widgets"
	"golang.org/x/sys/windows"
)

// NotifyConfig 单条拦截提示。
// ShowNotification 不会创建多个窗口，会把多条提示合并到同一个窗口里。
type NotifyConfig struct {
	Title      string
	TitleIcon  interface{}
	Message    string
	SubMessage string
	Detail     string

	Icon      interface{}
	LeftColor uint32
	Timeout   int

	OnIgnore    func()
	OnWhitelist func()
}

// ShowNotification 追加一条提示。
func ShowNotification(cfg NotifyConfig) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10
	}
	if cfg.LeftColor == 0 {
		cfg.LeftColor = 0x2F2FD3
	}
	notifyMgrAdd(cfg)
}

func safeGo(fn func()) {
	if fn == nil {
		return
	}
	go func() {
		defer func() { _ = recover() }()
		fn()
	}()
}

type notifyItem struct {
	name        string
	path        string
	detail      string
	icon        windows.Handle
	onWhitelist func()
}

type notifyState struct {
	title     string
	leftColor core.Color
	timeout   int
	onIgnore  func()
	items     []notifyItem
}

type notifyManager struct {
	mu          sync.Mutex
	ready       chan struct{}
	readyClosed bool
	initErr     error
	pending     []NotifyConfig
	app         *core.App
	view        *notifyView
	hovering    bool
	hideTimer   *time.Timer
	hideToken   uint64

	state notifyState
}

type notifyView struct {
	scene *widgets.Scene
	root  *widgets.Panel
	card  *widgets.Panel

	accent        *widgets.Panel
	headerDivider *widgets.Panel
	footerDivider *widgets.Panel

	titleLabel  *widgets.Label
	detailLabel *widgets.Label

	closeBtn     *widgets.Button
	ignoreBtn    *widgets.Button
	whitelistBtn *widgets.Button
	dismissBtn   *widgets.Button

	rows          []notifyRow
	titleIconRect core.Rect
}

type notifyRow struct {
	panel   *widgets.Panel
	iconBox *widgets.Panel
	name    *widgets.Label
	path    *widgets.Label
	divider *widgets.Panel
}

const (
	maxVisibleNotifyRows = 3

	wsPopup        = 0x80000000
	wsExTopmost    = 0x00000008
	wsExToolWindow = 0x00000080
	wsExNoActivate = 0x08000000

	swHide           = 0
	swShownoactivate = 4

	swpNoActivate = 0x0010

	spiGetWorkArea = 0x0030
)

var (
	gNotify notifyManager

	user32 = windows.NewLazySystemDLL("user32.dll")
	gdi32  = windows.NewLazySystemDLL("gdi32.dll")

	procShowWindow            = user32.NewProc("ShowWindow")
	procUpdateWindow          = user32.NewProc("UpdateWindow")
	procSetWindowPos          = user32.NewProc("SetWindowPos")
	procSystemParametersInfoW = user32.NewProc("SystemParametersInfoW")
	procSetWindowRgn          = user32.NewProc("SetWindowRgn")
	procDestroyIcon           = user32.NewProc("DestroyIcon")

	procCreateRoundRectRgn = gdi32.NewProc("CreateRoundRectRgn")
)

func notifyMgrAdd(cfg NotifyConfig) {
	gNotify.mu.Lock()
	gNotify.pending = append(gNotify.pending, cfg)
	start := false
	if gNotify.ready == nil {
		gNotify.ready = make(chan struct{})
		gNotify.readyClosed = false
		start = true
	}
	ready := gNotify.ready
	gNotify.mu.Unlock()

	if start {
		go gNotify.uiLoop()
	}

	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		return
	}

	gNotify.mu.Lock()
	app := gNotify.app
	initErr := gNotify.initErr
	gNotify.mu.Unlock()
	if initErr != nil || app == nil {
		return
	}

	_ = app.Post(func() {
		gNotify.drainPendingOnUI(true)
	})
}

func (m *notifyManager) uiLoop() {
	opts := core.Options{
		ClassName:      "BlockAdsNotify",
		Title:          "block-ads notify",
		Width:          388,
		Height:         164,
		Style:          wsPopup | core.WSClipChildren | core.WSClipSiblings,
		ExStyle:        wsExTopmost | wsExToolWindow | wsExNoActivate,
		Cursor:         core.CursorArrow,
		Background:     core.RGB(244, 246, 249),
		DoubleBuffered: true,
		RenderMode:     core.RenderModeAuto,
	}

	opts.OnMouseMove = func(_ *core.App, _ core.MouseEvent) {
		m.handleMouseMoveOnUI()
	}
	opts.OnMouseLeave = func(_ *core.App) {
		m.handleMouseLeaveOnUI()
	}

	widgets.BindScene(&opts, widgets.SceneHooks{
		OnCreate: m.onCreate,
		OnResize: m.onResize,
		AfterPaint: func(app *core.App, _ *widgets.Scene, canvas *core.Canvas) {
			m.afterPaint(app, canvas)
		},
		OnDestroy: m.onDestroy,
	})

	app, err := core.NewApp(opts)
	if err != nil {
		m.finishInit(nil, err)
		return
	}

	m.mu.Lock()
	m.app = app
	m.mu.Unlock()

	if err := app.Init(); err != nil {
		m.finishInit(nil, err)
		return
	}

	m.finishInit(app, nil)
	app.Run()
}

func (m *notifyManager) finishInit(app *core.App, err error) {
	m.mu.Lock()
	if err != nil {
		m.initErr = err
		m.app = nil
	} else {
		m.app = app
	}
	if m.ready != nil && !m.readyClosed {
		close(m.ready)
		m.readyClosed = true
	}
	m.mu.Unlock()
}

func (m *notifyManager) onCreate(app *core.App, scene *widgets.Scene) error {
	view := newNotifyView(scene, m)
	m.mu.Lock()
	m.view = view
	m.mu.Unlock()

	m.drainPendingOnUI(false)
	if len(m.state.items) == 0 {
		hideWindow(app.Handle())
	}
	return nil
}

func (m *notifyManager) onResize(app *core.App, _ *widgets.Scene, size core.Size) {
	if m.view == nil || size.Width <= 0 || size.Height <= 0 {
		return
	}
	m.view.layout(app, size)
}

func (m *notifyManager) onDestroy(_ *core.App, _ *widgets.Scene) {
	m.mu.Lock()
	if m.hideTimer != nil {
		m.hideTimer.Stop()
		m.hideTimer = nil
	}
	m.app = nil
	m.view = nil
	m.mu.Unlock()
	m.resetStateOnUI()
}

func (m *notifyManager) handleMouseMoveOnUI() {
	m.mu.Lock()
	m.hovering = true
	if m.hideTimer != nil {
		m.hideTimer.Stop()
		m.hideTimer = nil
	}
	m.mu.Unlock()
}

func (m *notifyManager) handleMouseLeaveOnUI() {
	m.mu.Lock()
	m.hovering = false
	timeout := m.state.timeout
	m.mu.Unlock()
	if len(m.state.items) == 0 {
		return
	}
	m.armHideTimer(timeout)
}

func (m *notifyManager) drainPendingOnUI(show bool) {
	m.mu.Lock()
	pending := append([]NotifyConfig(nil), m.pending...)
	m.pending = nil
	app := m.app
	view := m.view
	m.mu.Unlock()

	if app == nil || view == nil {
		return
	}

	changed := false
	for _, cfg := range pending {
		m.applyConfigOnUI(cfg)
		changed = true
	}
	if !changed {
		return
	}

	m.presentOnUI(show)
}

func (m *notifyManager) applyConfigOnUI(cfg NotifyConfig) {
	if cfg.Title != "" {
		m.state.title = cfg.Title
	}
	if cfg.LeftColor != 0 {
		m.state.leftColor = core.Color(cfg.LeftColor)
	}
	if cfg.Timeout > 0 {
		m.state.timeout = cfg.Timeout
	}
	m.state.onIgnore = cfg.OnIgnore

	item := notifyItem{
		name:        strings.TrimSpace(cfg.Message),
		path:        strings.TrimSpace(cfg.SubMessage),
		detail:      strings.TrimSpace(cfg.Detail),
		icon:        asHICON(cfg.Icon),
		onWhitelist: cfg.OnWhitelist,
	}
	if item.name == "" {
		item.name = "未知程序"
	}

	m.state.items = append([]notifyItem{item}, m.state.items...)
	if len(m.state.items) > 20 {
		for _, stale := range m.state.items[20:] {
			destroyIconHandle(stale.icon)
		}
		m.state.items = m.state.items[:20]
	}
}

func (m *notifyManager) presentOnUI(show bool) {
	if m.app == nil || m.view == nil || len(m.state.items) == 0 {
		return
	}

	m.view.syncFromState(m.state)
	size := m.view.outerSize(m.app, len(m.state.items))
	m.view.layout(m.app, size)
	positionNotifyWindow(m.app, size)

	if show {
		showWindowNoActivate(m.app.Handle())
		updateWindow(m.app.Handle())
	}

	m.armHideTimer(m.state.timeout)
}

func (m *notifyManager) armHideTimer(timeout int) {
	if timeout <= 0 {
		return
	}

	m.mu.Lock()
	if m.hideTimer != nil {
		m.hideTimer.Stop()
	}
	m.hideToken++
	token := m.hideToken
	app := m.app
	m.hideTimer = time.AfterFunc(time.Duration(timeout)*time.Second, func() {
		m.mu.Lock()
		if token != m.hideToken || m.hovering || app == nil {
			m.mu.Unlock()
			return
		}
		m.mu.Unlock()

		_ = app.Post(func() {
			m.mu.Lock()
			sameToken := token == m.hideToken
			hovering := m.hovering
			m.mu.Unlock()
			if !sameToken || hovering {
				return
			}
			m.hideAndResetOnUI()
		})
	})
	m.mu.Unlock()
}

func (m *notifyManager) hideAndResetOnUI() {
	if m.app == nil {
		return
	}

	m.mu.Lock()
	m.hovering = false
	m.hideToken++
	if m.hideTimer != nil {
		m.hideTimer.Stop()
		m.hideTimer = nil
	}
	m.mu.Unlock()

	hideWindow(m.app.Handle())
	m.resetStateOnUI()
	if m.view != nil {
		m.view.syncFromState(m.state)
	}
}

func (m *notifyManager) resetStateOnUI() {
	for _, item := range m.state.items {
		destroyIconHandle(item.icon)
	}
	m.state = notifyState{}
}

func (m *notifyManager) onDismissClick() {
	m.hideAndResetOnUI()
}

func (m *notifyManager) onIgnoreClick() {
	cb := m.state.onIgnore
	m.hideAndResetOnUI()
	safeGo(cb)
}

func (m *notifyManager) onWhitelistClick() {
	var cb func()
	if len(m.state.items) > 0 {
		cb = m.state.items[0].onWhitelist
	}
	m.hideAndResetOnUI()
	safeGo(cb)
}

func (m *notifyManager) afterPaint(app *core.App, canvas *core.Canvas) {
	if m.view == nil || len(m.state.items) == 0 {
		return
	}

	drawShieldGlyph(canvas, m.view.titleIconRect, m.state.leftColor)

	visible := len(m.state.items)
	if visible > len(m.view.rows) {
		visible = len(m.view.rows)
	}
	for i := 0; i < visible; i++ {
		iconRect := insetRect(m.view.rows[i].iconBox.Bounds(), app.DP(7))
		if m.state.items[i].icon != 0 {
			drawRawIcon(canvas, m.state.items[i].icon, iconRect)
			continue
		}
		drawWarningGlyph(canvas, iconRect)
	}
}

func newNotifyView(scene *widgets.Scene, mgr *notifyManager) *notifyView {
	root := scene.Root()
	root.SetLayout(widgets.AbsoluteLayout{})

	view := &notifyView{
		scene:         scene,
		root:          root,
		card:          widgets.NewPanel("notify-card"),
		accent:        widgets.NewPanel("notify-accent"),
		headerDivider: widgets.NewPanel("notify-header-divider"),
		footerDivider: widgets.NewPanel("notify-footer-divider"),
		titleLabel: newLabel(
			"notify-title",
			widgets.TextStyle{
				Font:   widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 16, Weight: 700},
				Color:  core.RGB(220, 44, 44),
				Format: core.DTVCenter | core.DTSingleLine | core.DTEndEllipsis,
			},
		),
		detailLabel: newLabel(
			"notify-detail",
			widgets.TextStyle{
				Font:   widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 11, Weight: 400},
				Color:  core.RGB(132, 138, 148),
				Format: core.DTVCenter | core.DTSingleLine | core.DTEndEllipsis,
			},
		),
		closeBtn:     newButton("notify-close", "×", closeButtonStyle()),
		ignoreBtn:    newButton("notify-ignore", "不再提示", mutedFooterButtonStyle()),
		whitelistBtn: newButton("notify-whitelist", "加入白名单", mutedFooterButtonStyle()),
		dismissBtn:   newButton("notify-dismiss", "知道了", accentFooterButtonStyle()),
		rows:         make([]notifyRow, 0, maxVisibleNotifyRows),
	}

	view.card.SetStyle(widgets.PanelStyle{
		Background:   core.RGB(255, 255, 255),
		BorderColor:  core.RGB(232, 235, 240),
		CornerRadius: 18,
		BorderWidth:  1,
	})
	view.accent.SetStyle(widgets.PanelStyle{
		Background: core.RGB(220, 44, 44),
	})
	view.headerDivider.SetStyle(widgets.PanelStyle{
		Background: core.RGB(237, 239, 243),
	})
	view.footerDivider.SetStyle(widgets.PanelStyle{
		Background: core.RGB(237, 239, 243),
	})

	view.closeBtn.SetOnClick(mgr.onDismissClick)
	view.ignoreBtn.SetOnClick(mgr.onIgnoreClick)
	view.whitelistBtn.SetOnClick(mgr.onWhitelistClick)
	view.dismissBtn.SetOnClick(mgr.onDismissClick)

	view.card.AddAll(
		view.accent,
		view.headerDivider,
		view.footerDivider,
		view.titleLabel,
		view.detailLabel,
		view.closeBtn,
		view.ignoreBtn,
		view.whitelistBtn,
		view.dismissBtn,
	)

	for i := 0; i < maxVisibleNotifyRows; i++ {
		row := notifyRow{
			panel:   widgets.NewPanel(fmt.Sprintf("notify-row-%d", i)),
			iconBox: widgets.NewPanel(fmt.Sprintf("notify-row-iconbox-%d", i)),
			name: newLabel(
				fmt.Sprintf("notify-row-name-%d", i),
				widgets.TextStyle{
					Font:   widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 15, Weight: 700},
					Color:  core.RGB(31, 35, 41),
					Format: core.DTVCenter | core.DTSingleLine | core.DTEndEllipsis,
				},
			),
			path: newLabel(
				fmt.Sprintf("notify-row-path-%d", i),
				widgets.TextStyle{
					Font:   widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 11, Weight: 400},
					Color:  core.RGB(126, 132, 140),
					Format: core.DTVCenter | core.DTSingleLine | core.DTEndEllipsis,
				},
			),
			divider: widgets.NewPanel(fmt.Sprintf("notify-row-divider-%d", i)),
		}

		row.iconBox.SetStyle(widgets.PanelStyle{
			Background:   core.RGB(246, 247, 250),
			BorderColor:  core.RGB(240, 242, 246),
			CornerRadius: 10,
			BorderWidth:  1,
		})
		row.divider.SetStyle(widgets.PanelStyle{
			Background: core.RGB(237, 239, 243),
		})

		row.panel.AddAll(row.iconBox, row.name, row.path)
		view.card.AddAll(row.panel, row.divider)
		view.rows = append(view.rows, row)
	}

	root.Add(view.card)
	return view
}

func (v *notifyView) syncFromState(state notifyState) {
	count := len(state.items)
	visibleRows := count
	if visibleRows > len(v.rows) {
		visibleRows = len(v.rows)
	}

	leftColor := state.leftColor
	if leftColor == 0 {
		leftColor = core.Color(0x2F2FD3)
	}
	v.accent.SetStyle(widgets.PanelStyle{Background: leftColor})

	v.titleLabel.SetText(composeNotifyTitle(state.title, count))
	v.titleLabel.SetStyle(widgets.TextStyle{
		Font:   widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 16, Weight: 700},
		Color:  leftColor,
		Format: core.DTVCenter | core.DTSingleLine | core.DTEndEllipsis,
	})

	v.detailLabel.SetText(composeNotifyDetail(state.items))
	v.footerDivider.SetVisible(count > 0)

	for i := range v.rows {
		show := i < visibleRows
		row := v.rows[i]
		row.panel.SetVisible(show)
		row.iconBox.SetVisible(show)
		row.name.SetVisible(show)
		row.path.SetVisible(show)
		row.divider.SetVisible(show && i < visibleRows-1)
		if !show {
			continue
		}
		row.name.SetText(state.items[i].name)
		row.path.SetText(state.items[i].path)
	}

	hasIgnore := state.onIgnore != nil
	hasWhitelist := false
	if count > 0 {
		hasWhitelist = state.items[0].onWhitelist != nil
	}
	v.ignoreBtn.SetVisible(hasIgnore)
	v.whitelistBtn.SetVisible(hasWhitelist)
	v.dismissBtn.SetVisible(count > 0)
}

func (v *notifyView) outerSize(app *core.App, itemCount int) core.Size {
	if itemCount < 1 {
		itemCount = 1
	}
	if itemCount > len(v.rows) {
		itemCount = len(v.rows)
	}

	shadow := app.DP(6)
	headerH := app.DP(52)
	rowH := app.DP(68)
	footerH := app.DP(38)

	return core.Size{
		Width:  app.DP(388),
		Height: shadow*2 + headerH + int32(itemCount)*rowH + footerH,
	}
}

func (v *notifyView) layout(app *core.App, size core.Size) {
	if size.Width <= 0 || size.Height <= 0 {
		return
	}

	shadow := app.DP(6)
	cardRect := core.Rect{
		X: shadow,
		Y: shadow,
		W: size.Width - shadow*2,
		H: size.Height - shadow*2,
	}

	v.card.SetBounds(cardRect)
	v.accent.SetBounds(core.Rect{X: cardRect.X, Y: cardRect.Y, W: app.DP(6), H: cardRect.H})

	headerH := app.DP(52)
	v.titleIconRect = core.Rect{X: cardRect.X + app.DP(16), Y: cardRect.Y + app.DP(14), W: app.DP(18), H: app.DP(18)}
	v.titleLabel.SetBounds(core.Rect{
		X: cardRect.X + app.DP(42),
		Y: cardRect.Y + app.DP(12),
		W: cardRect.W - app.DP(90),
		H: app.DP(24),
	})
	v.closeBtn.SetBounds(core.Rect{
		X: cardRect.X + cardRect.W - app.DP(34),
		Y: cardRect.Y + app.DP(12),
		W: app.DP(20),
		H: app.DP(20),
	})

	headerDividerY := cardRect.Y + headerH - 1
	v.headerDivider.SetBounds(core.Rect{
		X: cardRect.X + app.DP(12),
		Y: headerDividerY,
		W: cardRect.W - app.DP(24),
		H: 1,
	})

	rowStartY := headerDividerY + app.DP(8)
	rowHeight := app.DP(64)
	rowStep := app.DP(68)
	for i, row := range v.rows {
		rowY := rowStartY + int32(i)*rowStep
		row.panel.SetBounds(core.Rect{
			X: cardRect.X + app.DP(18),
			Y: rowY,
			W: cardRect.W - app.DP(36),
			H: rowHeight,
		})
		row.iconBox.SetBounds(core.Rect{
			X: cardRect.X + app.DP(18),
			Y: rowY + app.DP(10),
			W: app.DP(40),
			H: app.DP(40),
		})
		row.name.SetBounds(core.Rect{
			X: cardRect.X + app.DP(72),
			Y: rowY + app.DP(8),
			W: cardRect.W - app.DP(92),
			H: app.DP(20),
		})
		row.path.SetBounds(core.Rect{
			X: cardRect.X + app.DP(72),
			Y: rowY + app.DP(30),
			W: cardRect.W - app.DP(92),
			H: app.DP(16),
		})
		row.divider.SetBounds(core.Rect{
			X: cardRect.X + app.DP(18),
			Y: rowY + rowHeight + app.DP(3),
			W: cardRect.W - app.DP(36),
			H: 1,
		})
	}

	footerH := app.DP(38)
	footerY := cardRect.Y + cardRect.H - footerH
	v.footerDivider.SetBounds(core.Rect{
		X: cardRect.X + app.DP(12),
		Y: footerY,
		W: cardRect.W - app.DP(24),
		H: 1,
	})

	btnY := footerY + app.DP(6)
	btnH := app.DP(24)
	btnGap := app.DP(4)
	right := cardRect.X + cardRect.W - app.DP(14)

	layoutBtn := func(btn *widgets.Button, width int32) {
		if !btn.Visible() {
			btn.SetBounds(core.Rect{})
			return
		}
		right -= width
		btn.SetBounds(core.Rect{X: right, Y: btnY, W: width, H: btnH})
		right -= btnGap
	}

	layoutBtn(v.dismissBtn, app.DP(54))
	layoutBtn(v.whitelistBtn, app.DP(78))
	layoutBtn(v.ignoreBtn, app.DP(68))

	detailW := right - (cardRect.X + app.DP(16))
	if detailW < app.DP(80) {
		detailW = app.DP(80)
	}
	v.detailLabel.SetBounds(core.Rect{
		X: cardRect.X + app.DP(16),
		Y: footerY + app.DP(8),
		W: detailW,
		H: app.DP(18),
	})
}

func composeNotifyTitle(base string, count int) string {
	base = strings.TrimSpace(base)
	if base == "" {
		base = "提示"
	}
	if count <= 1 {
		return base
	}
	return fmt.Sprintf("%s %d 个", base, count)
}

func composeNotifyDetail(items []notifyItem) string {
	if len(items) == 0 {
		return ""
	}
	if len(items) == 1 {
		if items[0].detail != "" {
			return items[0].detail
		}
		return "检测到拦截提示"
	}

	detail := items[0].detail
	if detail == "" {
		return fmt.Sprintf("检测到 %d 个拦截项", len(items))
	}
	return fmt.Sprintf("%s，另有 %d 条", detail, len(items)-1)
}

func newLabel(id string, style widgets.TextStyle) *widgets.Label {
	label := widgets.NewLabel(id, "")
	label.SetStyle(style)
	return label
}

func newButton(id, text string, style widgets.ButtonStyle) *widgets.Button {
	btn := widgets.NewButton(id, text, widgets.ModeCustom)
	btn.SetStyle(style)
	return btn
}

func closeButtonStyle() widgets.ButtonStyle {
	return widgets.ButtonStyle{
		Font:         widgets.FontSpec{Face: "Segoe UI", SizeDP: 12, Weight: 700},
		TextColor:    core.RGB(146, 151, 160),
		DownText:     core.RGB(88, 93, 103),
		Background:   core.RGB(255, 255, 255),
		Hover:        core.RGB(245, 246, 249),
		Pressed:      core.RGB(235, 238, 243),
		Border:       core.RGB(255, 255, 255),
		CornerRadius: 10,
		PadDP:        6,
	}
}

func mutedFooterButtonStyle() widgets.ButtonStyle {
	return widgets.ButtonStyle{
		Font:         widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 11, Weight: 500},
		TextColor:    core.RGB(134, 139, 147),
		DownText:     core.RGB(91, 97, 107),
		Background:   core.RGB(255, 255, 255),
		Hover:        core.RGB(246, 247, 250),
		Pressed:      core.RGB(238, 241, 245),
		Border:       core.RGB(255, 255, 255),
		CornerRadius: 8,
		PadDP:        8,
	}
}

func accentFooterButtonStyle() widgets.ButtonStyle {
	return widgets.ButtonStyle{
		Font:         widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 11, Weight: 600},
		TextColor:    core.RGB(220, 44, 44),
		DownText:     core.RGB(180, 34, 34),
		Background:   core.RGB(255, 255, 255),
		Hover:        core.RGB(255, 244, 244),
		Pressed:      core.RGB(255, 233, 233),
		Border:       core.RGB(255, 255, 255),
		CornerRadius: 8,
		PadDP:        8,
	}
}

func positionNotifyWindow(app *core.App, size core.Size) {
	if app == nil || app.Handle() == 0 {
		return
	}

	area := workArea()
	marginX := app.DP(18)
	marginY := app.DP(28)
	x := area.Right - size.Width - marginX
	y := area.Bottom - size.Height - marginY
	if x < area.Left {
		x = area.Left
	}
	if y < area.Top {
		y = area.Top
	}

	setWindowPos(app.Handle(), x, y, size.Width, size.Height)
	setRoundedRegion(app.Handle(), size.Width, size.Height, app.DP(20))
}

func showWindowNoActivate(hwnd windows.Handle) {
	if hwnd == 0 {
		return
	}
	procShowWindow.Call(uintptr(hwnd), swShownoactivate)
}

func hideWindow(hwnd windows.Handle) {
	if hwnd == 0 {
		return
	}
	procShowWindow.Call(uintptr(hwnd), swHide)
}

func updateWindow(hwnd windows.Handle) {
	if hwnd == 0 {
		return
	}
	procUpdateWindow.Call(uintptr(hwnd))
}

func setWindowPos(hwnd windows.Handle, x, y, w, h int32) {
	const hwndTopmost = ^uintptr(0)
	procSetWindowPos.Call(
		uintptr(hwnd),
		hwndTopmost,
		uintptr(x),
		uintptr(y),
		uintptr(w),
		uintptr(h),
		swpNoActivate,
	)
}

func setRoundedRegion(hwnd windows.Handle, w, h, radius int32) {
	if hwnd == 0 || w <= 0 || h <= 0 {
		return
	}
	if radius < 1 {
		radius = 1
	}
	rgn, _, _ := procCreateRoundRectRgn.Call(
		0,
		0,
		uintptr(w+1),
		uintptr(h+1),
		uintptr(radius),
		uintptr(radius),
	)
	if rgn == 0 {
		return
	}
	procSetWindowRgn.Call(uintptr(hwnd), rgn, 1)
}

type winRect struct {
	Left   int32
	Top    int32
	Right  int32
	Bottom int32
}

func workArea() winRect {
	var rect winRect
	ret, _, _ := procSystemParametersInfoW.Call(
		spiGetWorkArea,
		0,
		uintptr(unsafe.Pointer(&rect)),
		0,
	)
	if ret == 0 {
		return winRect{Left: 0, Top: 0, Right: 1920, Bottom: 1080}
	}
	return rect
}

func asHICON(v interface{}) windows.Handle {
	switch t := v.(type) {
	case windows.Handle:
		return t
	case syscall.Handle:
		return windows.Handle(t)
	case uintptr:
		return windows.Handle(t)
	default:
		return 0
	}
}

func destroyIconHandle(h windows.Handle) {
	if h == 0 {
		return
	}
	procDestroyIcon.Call(uintptr(h))
}

func insetRect(rect core.Rect, inset int32) core.Rect {
	rect.X += inset
	rect.Y += inset
	rect.W -= inset * 2
	rect.H -= inset * 2
	if rect.W < 1 {
		rect.W = 1
	}
	if rect.H < 1 {
		rect.H = 1
	}
	return rect
}

func drawRawIcon(canvas *core.Canvas, icon windows.Handle, rect core.Rect) {
	if canvas == nil || icon == 0 {
		return
	}
	tmp := struct {
		handle windows.Handle
	}{handle: icon}
	_ = canvas.DrawIcon((*core.Icon)(unsafe.Pointer(&tmp)), rect)
}

func drawShieldGlyph(canvas *core.Canvas, rect core.Rect, accent core.Color) {
	if canvas == nil || rect.W <= 0 || rect.H <= 0 {
		return
	}
	if accent == 0 {
		accent = core.RGB(220, 44, 44)
	}

	outer := shieldPoints(rect)
	inner := shieldPoints(insetRect(rect, max32(1, rect.W/7)))
	_ = canvas.FillPolygon(outer, accent)
	_ = canvas.FillPolygon(inner, core.RGB(255, 255, 255))

	lineRect := core.Rect{
		X: rect.X + rect.W/2 - max32(1, rect.W/14),
		Y: rect.Y + rect.H/4,
		W: max32(2, rect.W/7),
		H: rect.H / 3,
	}
	dotRect := core.Rect{
		X: rect.X + rect.W/2 - max32(1, rect.W/14),
		Y: rect.Y + rect.H - rect.H/4,
		W: max32(2, rect.W/7),
		H: max32(2, rect.H/8),
	}
	_ = canvas.FillRoundRect(lineRect, max32(1, lineRect.W/2), accent)
	_ = canvas.FillRoundRect(dotRect, max32(1, dotRect.W/2), accent)
}

func drawWarningGlyph(canvas *core.Canvas, rect core.Rect) {
	if canvas == nil || rect.W <= 0 || rect.H <= 0 {
		return
	}

	outer := []core.Point{
		{X: rect.X + rect.W/2, Y: rect.Y},
		{X: rect.X + rect.W, Y: rect.Y + rect.H},
		{X: rect.X, Y: rect.Y + rect.H},
	}
	inner := []core.Point{
		{X: rect.X + rect.W/2, Y: rect.Y + max32(1, rect.H/10)},
		{X: rect.X + rect.W - max32(1, rect.W/10), Y: rect.Y + rect.H - max32(1, rect.H/10)},
		{X: rect.X + max32(1, rect.W/10), Y: rect.Y + rect.H - max32(1, rect.H/10)},
	}
	_ = canvas.FillPolygon(outer, core.RGB(35, 38, 43))
	_ = canvas.FillPolygon(inner, core.RGB(255, 214, 10))

	lineRect := core.Rect{
		X: rect.X + rect.W/2 - max32(1, rect.W/16),
		Y: rect.Y + rect.H/3 - max32(1, rect.H/16),
		W: max32(2, rect.W/8),
		H: rect.H / 3,
	}
	dotRect := core.Rect{
		X: rect.X + rect.W/2 - max32(1, rect.W/16),
		Y: rect.Y + rect.H - rect.H/4,
		W: max32(2, rect.W/8),
		H: max32(2, rect.H/10),
	}
	_ = canvas.FillRoundRect(lineRect, max32(1, lineRect.W/2), core.RGB(35, 38, 43))
	_ = canvas.FillRoundRect(dotRect, max32(1, dotRect.W/2), core.RGB(35, 38, 43))
}

func shieldPoints(rect core.Rect) []core.Point {
	return []core.Point{
		{X: rect.X + rect.W/2, Y: rect.Y},
		{X: rect.X + rect.W - max32(1, rect.W/10), Y: rect.Y + rect.H/4},
		{X: rect.X + rect.W - max32(1, rect.W/6), Y: rect.Y + rect.H - max32(1, rect.H/5)},
		{X: rect.X + rect.W/2, Y: rect.Y + rect.H},
		{X: rect.X + max32(1, rect.W/6), Y: rect.Y + rect.H - max32(1, rect.H/5)},
		{X: rect.X + max32(1, rect.W/10), Y: rect.Y + rect.H/4},
	}
}

func max32(a, b int32) int32 {
	if a > b {
		return a
	}
	return b
}
