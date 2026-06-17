//go:build windows

package main

import (
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/AzureIvory/winui/core"
	"github.com/AzureIvory/winui/widgets"
)

// ---- 目录选择（SHBrowseForFolder，纯 syscall）----
var (
	shell32             = syscall.NewLazyDLL("shell32.dll")
	ole32               = syscall.NewLazyDLL("ole32.dll")
	procSHBrowse        = shell32.NewProc("SHBrowseForFolderW")
	procSHGetPathFromID = shell32.NewProc("SHGetPathFromIDListW")
	procCoTaskMemFree   = ole32.NewProc("CoTaskMemFree")
)

const (
	maxPath     = 260
	bifReturnOnly = 0x00000001
	bifNewStyle   = 0x00000040
)

type browseInfo struct {
	Owner, Root  uintptr
	DisplayName  *uint16
	Title        *uint16
	Flags        uint32
	Callback     uintptr
	LParam       uintptr
	Image        int32
}

func browseForFolder(owner uintptr) string {
	title, _ := syscall.UTF16PtrFromString("选择更新目录")
	var dn [maxPath]uint16
	bi := browseInfo{Owner: owner, DisplayName: &dn[0], Title: title, Flags: bifReturnOnly | bifNewStyle}
	pidl, _, _ := procSHBrowse.Call(uintptr(unsafe.Pointer(&bi)))
	if pidl == 0 {
		return ""
	}
	defer procCoTaskMemFree.Call(pidl)
	var p [maxPath]uint16
	ok, _, _ := procSHGetPathFromID.Call(pidl, uintptr(unsafe.Pointer(&p[0])))
	if ok == 0 {
		return ""
	}
	return syscall.UTF16ToString(p[:])
}

// ---- 表单 ----
var (
	st struct {
		app                 *core.App
		scene               *widgets.Scene
		root                *widgets.Panel
	lbUpdateDir         *widgets.Label
		inpUpdateDir        *widgets.EditBox
		lbVersion           *widgets.Label
		inpVersion          *widgets.EditBox
		lbMsupp             *widgets.Label
		lbNotes             *widgets.Label
		lbRun               *widgets.Label
		lbBase1             *widgets.Label
		lbBase2             *widgets.Label
		inpMsupp            *widgets.EditBox
		inpNotes            *widgets.EditBox
		chkMand             *widgets.CheckBox
		inpRun              *widgets.EditBox
		inpBase1            *widgets.EditBox
		inpBase2            *widgets.EditBox
		btnPick, btnGen     *widgets.Button
		msg                 *widgets.Label
		// 每行的标签，用于布局
		labels []*widgets.Label
	}
)

func runGUI() {
	opts := core.Options{
		ClassName:      "CreateJsonPublisher",
		Title:          "更新发布工具",
		Width:          660,
		Height:         600,
		MinWidth:       580,
		MinHeight:      500,
		Style:          core.DefaultWindowStyle,
		ExStyle:        core.DefaultWindowExStyle,
		Cursor:         core.CursorArrow,
		Background:     core.RGB(248, 250, 252),
		DoubleBuffered: true,
		RenderMode:     core.RenderModeAuto,
	}
	widgets.BindScene(&opts, widgets.SceneHooks{
		OnCreate: onCreate,
		OnResize: func(_ *core.App, _ *widgets.Scene, size core.Size) { layout(size) },
	})
	app, err := core.NewApp(opts)
	if err != nil {
		return
	}
	if err := app.Init(); err != nil {
		return
	}
	app.Run()
}

func onCreate(app *core.App, scene *widgets.Scene) error {
	st.app = app
	st.scene = scene
	scene.SetTheme(widgets.DefaultTheme())
	st.root = scene.Root()
	st.root.SetStyle(widgets.PanelStyle{Background: core.RGB(248, 250, 252)})

	// 第一行：更新目录 + 浏览按钮
	st.lbUpdateDir = mkLabel("更新目录:")
	st.inpUpdateDir = mkEdit(filepath.Join(exeDir(), "update"), "程序目录下的 update 子目录")
	st.btnPick = mkButton("浏览...", softBtn())
	st.btnPick.SetOnClick(func() {
		if d := browseForFolder(uintptr(app.Handle())); d != "" {
			st.inpUpdateDir.SetText(relUpdateDir(d))
		}
	})

	st.lbVersion = mkLabel("版本号: *")
	st.inpVersion = mkEdit("", "如 1.2")

	st.lbMsupp = mkLabel("最低支持版本:")
	st.inpMsupp = mkEdit("0", "如 1.0")

	st.lbNotes = mkLabel("更新说明:")
	st.inpNotes = mkEdit("", "1.2版本\n优化UI...")
	st.inpNotes.SetMultiline(true)
	st.inpNotes.SetWordWrap(true)
	st.inpNotes.SetVerticalScroll(true)

	// 强制更新（无标签，自身带文字）放在 msg 区上方
	st.chkMand = widgets.NewCheckBox("mand", "强制更新", widgets.ModeCustom)

	st.lbRun = mkLabel("更新后运行:")
	st.inpRun = mkEdit("", "如 UI.exe(逗号分隔)")

	st.lbBase1 = mkLabel("URL 基址1:")
	st.inpBase1 = mkEdit(defaultBase1, "下载基址1")

	st.lbBase2 = mkLabel("URL 基址2:")
	st.inpBase2 = mkEdit(defaultBase2, "下载基址2")

	st.btnGen = mkButton("生成 update.json / sync.json", primaryBtn())
	st.btnGen.SetOnClick(doGenerate)

	st.msg = widgets.NewLabel("msg", "")
	st.msg.SetStyle(widgets.TextStyle{
		Font:   widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 13, Weight: 500},
		Color:  core.RGB(120, 132, 158),
		Format: core.DTVCenter | core.DTSingleLine | core.DTEndEllipsis,
	})

	// 加入根面板：标签 + 控件
	st.root.AddAll(
		st.lbUpdateDir, st.inpUpdateDir, st.btnPick,
		st.lbVersion, st.inpVersion,
		st.lbMsupp, st.inpMsupp,
		st.lbNotes, st.inpNotes,
		st.chkMand,
		st.lbRun, st.inpRun,
		st.lbBase1, st.inpBase1,
		st.lbBase2, st.inpBase2,
		st.btnGen,
		st.msg,
	)

	layout(app.ClientSize())

	// 控件加入场景后再填默认值，确保 runOnUI 正确投递、渲染可见。
	st.inpUpdateDir.SetText(filepath.Join(exeDir(), "update"))
	st.inpMsupp.SetText("0")
	st.inpBase1.SetText(defaultBase1)
	st.inpBase2.SetText(defaultBase2)
	return nil
}

func mkLabel(text string) *widgets.Label {
	l := widgets.NewLabel("lbl", text)
	l.SetStyle(widgets.TextStyle{
		Font:   widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 14, Weight: 600},
		Color:  core.RGB(40, 50, 70),
		Format: core.DTVCenter | core.DTSingleLine | core.DTEndEllipsis,
	})
	return l
}

func mkEdit(def, placeholder string) *widgets.EditBox {
	e := widgets.NewEditBox("e", widgets.ModeCustom)
	e.SetText(def)
	e.SetPlaceholder(placeholder)
	e.SetStyle(widgets.EditStyle{
		Font:         widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 14, Weight: 400},
		TextColor:    core.RGB(40, 50, 70),
		Background:   core.RGB(255, 255, 255),
		BorderColor:  core.RGB(214, 224, 241),
		HoverBorder:  core.RGB(96, 165, 250),
		FocusBorder:  core.RGB(47, 104, 243),
		PaddingDP:    8,
		CornerRadius: 8,
	})
	return e
}

func mkButton(text string, style widgets.ButtonStyle) *widgets.Button {
	b := widgets.NewButton("btn", text, widgets.ModeCustom)
	b.SetStyle(style)
	return b
}

func softBtn() widgets.ButtonStyle {
	return widgets.ButtonStyle{
		Font:        widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 14, Weight: 600},
		TextAlign:   widgets.AlignCenter,
		TextColor:   core.RGB(41, 52, 77),
		Background:  core.RGB(255, 255, 255),
		Hover:       core.RGB(242, 246, 253),
		Pressed:     core.RGB(232, 238, 250),
		Disabled:    core.RGB(245, 248, 252),
		Border:      core.RGB(220, 228, 242),
		Shape:       widgets.ButtonShapePill,
		PadDP:       10,
		TextInsetDP: 14,
	}
}

func primaryBtn() widgets.ButtonStyle {
	return widgets.ButtonStyle{
		Font:        widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 15, Weight: 700},
		TextAlign:   widgets.AlignCenter,
		TextColor:   core.RGB(255, 255, 255),
		Background:  core.RGB(47, 104, 243),
		Hover:       core.RGB(38, 93, 228),
		Pressed:     core.RGB(31, 78, 200),
		Disabled:    core.RGB(160, 181, 235),
		Shape:       widgets.ButtonShapePill,
		PadDP:       12,
		TextInsetDP: 16,
	}
}

// layout 绝对坐标布局。控件顺序与创建顺序一致。
// layout 用绝对坐标摆放每个控件（标签与控件 1:1 对应，不靠索引计数）。
func layout(size core.Size) {
	w := size.Width
	if w <= 0 {
		return
	}
	const (
		padX   = 24
		lablW  = 130
		inputH = 32
		gap    = 10
		notesH = 110
	)
	inputW := w - padX*2 - lablW
	if inputW < 200 {
		inputW = 200
	}
	x := int32(padX)
	y := int32(padX)
	// 标签在左侧 lablW 区，控件在右侧。每行下移 (h+gap)。
	row := func(lbl *widgets.Label, ctrl widgets.Widget, h int32) {
		lbl.SetBounds(core.Rect{X: x, Y: y, W: lablW, H: h})
		ctrl.SetBounds(core.Rect{X: x + lablW, Y: y, W: inputW, H: h})
		y += h + gap
	}

	// 更新目录行：输入框要给浏览按钮让出右段宽度。
	st.lbUpdateDir.SetBounds(core.Rect{X: x, Y: y, W: lablW, H: inputH})
	pickW := int32(80)
	st.inpUpdateDir.SetBounds(core.Rect{X: x + lablW, Y: y, W: inputW - pickW - gap, H: inputH})
	st.btnPick.SetBounds(core.Rect{X: x + lablW + inputW - pickW, Y: y, W: pickW, H: inputH})
	y += inputH + gap

	row(st.lbVersion, st.inpVersion, inputH)
	row(st.lbMsupp, st.inpMsupp, inputH)

	// 更新说明：多行
	st.lbNotes.SetBounds(core.Rect{X: x, Y: y, W: lablW, H: notesH})
	st.inpNotes.SetBounds(core.Rect{X: x + lablW, Y: y, W: inputW, H: notesH})
	y += notesH + gap

	// 强制更新（CheckBox 自带文字，无左侧标签，占满右侧）
	st.chkMand.SetBounds(core.Rect{X: x + lablW, Y: y, W: inputW, H: inputH})
	y += inputH + gap

	row(st.lbRun, st.inpRun, inputH)
	row(st.lbBase1, st.inpBase1, inputH)
	row(st.lbBase2, st.inpBase2, inputH)

	// 生成按钮 + 消息
	st.btnGen.SetBounds(core.Rect{X: x + lablW, Y: y, W: inputW, H: 40})
	y += 40 + gap
	st.msg.SetBounds(core.Rect{X: x, Y: y, W: w - padX*2, H: 24})
}

// relUpdateDir 把选中目录尽量转成相对程序目录的子目录名；否则原样返回。
func relUpdateDir(picked string) string {
	picked = filepath.Clean(picked)
	base := filepath.Clean(exeDir())
	if rel, err := filepath.Rel(base, picked); err == nil && !strings.HasPrefix(rel, "..") {
		return rel
	}
	return picked
}

// doGenerate 从表单读取并生成。
func doGenerate() {
	version := strings.TrimSpace(st.inpVersion.TextValue())
	if version == "" {
		st.msg.SetStyle(widgets.TextStyle{
			Font: widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 13, Weight: 600},
			Color: core.RGB(220, 38, 38), Format: core.DTVCenter | core.DTSingleLine,
		})
		st.msg.SetText("请填写版本号")
		return
	}
	updatedir := strings.TrimSpace(st.inpUpdateDir.TextValue())
	if updatedir == "" {
		updatedir = "update"
	}
	o := genOptions{
		BaseDir:   exeDir(),
		UpdateDir: updatedir,
		Version:   version,
		Msupport:  strings.TrimSpace(st.inpMsupp.TextValue()),
		Mandatory: st.chkMand.IsChecked(),
		Notes:     st.inpNotes.TextValue(),
		RunList:   strings.TrimSpace(st.inpRun.TextValue()),
		Base1:     strings.TrimSpace(st.inpBase1.TextValue()),
		Base2:     strings.TrimSpace(st.inpBase2.TextValue()),
		OutUpdate: "update.json",
		OutSync:   "sync.json",
	}
	stats, err := generate(o)
	if err != nil {
		st.msg.SetStyle(widgets.TextStyle{
			Font: widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 13, Weight: 600},
			Color: core.RGB(220, 38, 38), Format: core.DTVCenter | core.DTSingleLine | core.DTEndEllipsis,
		})
		st.msg.SetText("失败: " + err.Error())
		return
	}
	st.msg.SetStyle(widgets.TextStyle{
		Font: widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 13, Weight: 600},
		Color: core.RGB(22, 163, 74), Format: core.DTVCenter | core.DTSingleLine | core.DTEndEllipsis,
	})
	st.msg.SetText("完成: " + strings.ReplaceAll(stats, "\n", "  "))
}
