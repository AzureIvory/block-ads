//go:build windows

package main

import (
	"sync"

	"github.com/AzureIvory/winui/core"
	"github.com/AzureIvory/winui/widgets"
)

const dtWordBreak uint32 = 0x00000010
const aboutVersionValue = "1.3"
const fakeConfirmMessage = "1.将会调用默认浏览器访问一次知乎\"zhihu.com\"\n2.设置HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\360Safe\\stat项中 noadpop 与 advtool_PopWndTracker 的键值\n3.设置%APPDATA%\\TabXExplorer\\config.ini 文件中 settings 节的 level 值\n4.设置HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\360Safe\\stat项中 noadpop 与 advtool_PopWndTracker 的键值\n5.将会在HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall新增一个火绒的安装项和\"DisplayIcon\"键\n6.将会在后台运行一个空壳程序\"Code.exe\"(vscode),其中窗口类名为\"CabinetWClass\",标题为\"控制面板\"。"

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
	// Source 标识来源："txt" 为云端只读基准，"custom" 为用户自定义（在 user_rules.json 的 add 段）。
	Source string
	// Disabled 表示该 txt 规则是否被用户禁用（对应 user_rules.json 的 disabled 段）。
	Disabled bool
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
	app          *core.App
	scene        *widgets.Scene
	icon         *core.Icon
	enlargeImage *core.Image
	restoreImage *core.Image
	// 按钮图标（在 buildAll 时加载，供按钮 SetImage 使用）。
	fakeImage     *core.Image
	gitImage      *core.Image
	startImage    *core.Image
	enableImage   *core.Image
	disabledImage *core.Image
	dir           string
	exe           string
	codeEx        string
	dat           *appDat

	stopCh   chan struct{}
	stopOnce sync.Once

	curKey            string
	filter            string
	selectedRuleIndex int
	selectedLogIndex  int
	panelFocus        string
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
	btnGit  *widgets.Button

	btnUpload *widgets.Button
	btnSync   *widgets.Button
	btnUpdate *widgets.Button
	btnAbout  *widgets.Button

	btnAdd       *widgets.Button
	btnEnabled   *widgets.Button // 仅看启用（开关）
	btnDisabled  *widgets.Button // 仅看禁用（开关）
	btnRuleFocus *widgets.Button

	// ruleFilter 控制规则列表筛选："all"（默认）/"enabled"/"disabled"。
	ruleFilter string

	btnLogOpen  *widgets.Button
	btnLogWhite *widgets.Button
	btnLogFocus *widgets.Button

	chkBoot   *widgets.CheckBox
	chkCode   *widgets.CheckBox
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

	// alertDialog 是 winui 自带风格的提示弹窗
	alertDialog *widgets.Panel
	alertLabel  *widgets.Label
	alertClose  *widgets.Button

	aboutDialog  *widgets.Panel
	aboutTitle   *widgets.Label
	aboutIcon    *widgets.Image
	aboutName    *widgets.Label
	aboutDesc    *widgets.Label
	aboutVersion *widgets.Label
	aboutGit     *widgets.Button
	aboutClose   *widgets.Button

	fakeConfirmDialog   *widgets.Panel
	fakeConfirmTitle    *widgets.Label
	fakeConfirmMessage  *widgets.Label
	fakeConfirmContinue *widgets.Button
	fakeConfirmCancel   *widgets.Button

	updateDialog  *widgets.Panel
	updateTitle   *widgets.Label
	updateVersion *widgets.Label
	updateDate    *widgets.Label
	updateNotes   *widgets.Label
	updateItems   *widgets.Label
	updateCheck   *widgets.Button
	updateGo      *widgets.Button
	updateClose   *widgets.Button
	updateWait    *widgets.AnimatedImage // 网络等待动画

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
	syncWait       *widgets.AnimatedImage // 网络等待动画

	uploadDialog *widgets.Panel
	uploadTitle  *widgets.Label
	uploadDesc   *widgets.Label
	uploadWarn   *widgets.Label
	uploadAll    *widgets.CheckBox
	uploadGo     *widgets.Button
	uploadClose  *widgets.Button
	uploadCancel *widgets.Button
	uploadChecks map[string]*widgets.CheckBox

	mdl  *uiMdl
	head *headCtl
	side *sideCtl
	rule *ruleCtl
	log  *logCtl
	dlg  *dlgCtl
}

func runNativeUI(dat *appDat, dir string) error {
	ui := newUI(dat, dir)

	opts := core.Options{
		ClassName:      "BlockAdsWinUI",
		Title:          "名单管理",
		Width:          980,
		Height:         720,
		Style:          core.DefaultWindowStyle,
		ExStyle:        core.DefaultWindowExStyle,
		Cursor:         core.CursorArrow,
		Background:     ui.col(245, 248, 252),
		DoubleBuffered: true,
		RenderMode:     core.RenderModeAuto,
	}

	if ico := loadWinUIIcon(); ico != nil {
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
