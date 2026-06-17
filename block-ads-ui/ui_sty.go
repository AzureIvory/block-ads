//go:build windows

package main

import (
	"github.com/AzureIvory/winui/core"
	"github.com/AzureIvory/winui/widgets"
)

type btnCfg struct {
	sz   int32
	wt   int32
	pad  int32
	ins  int32
	gap  int32
	txt  core.Color
	down core.Color
	off  core.Color
	bg   core.Color
	hov  core.Color
	prs  core.Color
	dis  core.Color
	brd  core.Color
}

// btnSty 统一生成 pill 按钮样式。
func (u *nativeUI) btnSty(cfg btnCfg) widgets.ButtonStyle {
	return widgets.ButtonStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei UI",
			SizeDP: cfg.sz,
			Weight: cfg.wt,
		},
		TextAlign:    widgets.AlignCenter,
		TextColor:    cfg.txt,
		DownText:     cfg.down,
		DisabledText: cfg.off,
		Background:   cfg.bg,
		Hover:        cfg.hov,
		Pressed:      cfg.prs,
		Disabled:     cfg.dis,
		Border:       cfg.brd,
		Shape:        widgets.ButtonShapePill,
		PadDP:        cfg.pad,
		TextInsetDP:  cfg.ins,
		GapDP:        cfg.gap,
	}
}

func (u *nativeUI) primaryButtonStyle() widgets.ButtonStyle {
	return u.btnSty(btnCfg{
		sz: 15, wt: 700, pad: 12, ins: 18, gap: 8,
		txt: u.col(255, 255, 255), down: u.col(255, 255, 255), off: u.col(225, 232, 243),
		bg: u.col(47, 104, 243), hov: u.col(38, 93, 228), prs: u.col(31, 78, 200),
		dis: u.col(160, 181, 235), brd: u.col(47, 104, 243),
	})
}

func (u *nativeUI) dangerButtonStyle() widgets.ButtonStyle {
	return u.btnSty(btnCfg{
		sz: 15, wt: 700, pad: 12, ins: 18, gap: 8,
		txt: u.col(255, 255, 255), down: u.col(255, 255, 255), off: u.col(245, 210, 210),
		bg: u.col(220, 38, 38), hov: u.col(200, 30, 30), prs: u.col(165, 24, 24),
		dis: u.col(240, 188, 188), brd: u.col(220, 38, 38),
	})
}

func (u *nativeUI) softButtonStyle() widgets.ButtonStyle {
	return u.btnSty(btnCfg{
		sz: 14, wt: 600, pad: 12, ins: 16, gap: 8,
		txt: u.col(41, 52, 77), down: u.col(41, 52, 77), off: u.col(171, 183, 206),
		bg: u.col(255, 255, 255), hov: u.col(242, 246, 253), prs: u.col(232, 238, 250),
		dis: u.col(245, 248, 252), brd: u.col(220, 228, 242),
	})
}

func (u *nativeUI) sideButtonStyle(active bool) widgets.ButtonStyle {
	if active {
		return u.btnSty(btnCfg{
			sz: 14, wt: 700, pad: 10, ins: 14, gap: 6,
			txt: u.col(47, 104, 243), down: u.col(47, 104, 243), off: u.col(130, 156, 214),
			bg: u.col(234, 242, 255), hov: u.col(229, 238, 255), prs: u.col(219, 232, 255),
			dis: u.col(240, 245, 255), brd: u.col(156, 190, 252),
		})
	}
	return u.btnSty(btnCfg{
		sz: 14, wt: 600, pad: 10, ins: 14, gap: 6,
		txt: u.col(31, 41, 55), down: u.col(31, 41, 55), off: u.col(171, 183, 206),
		bg: u.col(250, 252, 255), hov: u.col(243, 247, 254), prs: u.col(236, 242, 252),
		dis: u.col(245, 248, 252), brd: u.col(226, 232, 243),
	})
}

func (u *nativeUI) sidebarActionStyle() widgets.ButtonStyle {
	return u.btnSty(btnCfg{
		sz: 13, wt: 600, pad: 8, ins: 12, gap: 6,
		txt: u.col(33, 45, 76), down: u.col(33, 45, 76), off: u.col(171, 183, 206),
		bg: u.col(244, 247, 252), hov: u.col(236, 242, 252), prs: u.col(228, 236, 250),
		dis: u.col(247, 249, 252), brd: u.col(228, 235, 246),
	})
}

func (u *nativeUI) compactPrimaryButtonStyle() widgets.ButtonStyle {
	return u.btnSty(btnCfg{
		sz: 12, wt: 700, pad: 7, ins: 10, gap: 6,
		txt: u.col(255, 255, 255), down: u.col(255, 255, 255), off: u.col(225, 232, 243),
		bg: u.col(47, 104, 243), hov: u.col(38, 93, 228), prs: u.col(31, 78, 200),
		dis: u.col(160, 181, 235), brd: u.col(47, 104, 243),
	})
}

func (u *nativeUI) compactSoftButtonStyle() widgets.ButtonStyle {
	return u.btnSty(btnCfg{
		sz: 12, wt: 600, pad: 7, ins: 10, gap: 6,
		txt: u.col(41, 52, 77), down: u.col(41, 52, 77), off: u.col(171, 183, 206),
		bg: u.col(255, 255, 255), hov: u.col(242, 246, 253), prs: u.col(232, 238, 250),
		dis: u.col(245, 248, 252), brd: u.col(220, 228, 242),
	})
}

// headerIconButtonStyle 是顶栏带图标按钮的样式，
func (u *nativeUI) headerIconButtonStyle() widgets.ButtonStyle {
	return u.btnSty(btnCfg{
		sz: 14, wt: 600, pad: 8, ins: 12, gap: 8,
		txt: u.col(41, 52, 77), down: u.col(41, 52, 77), off: u.col(171, 183, 206),
		bg: u.col(255, 255, 255), hov: u.col(242, 246, 253), prs: u.col(232, 238, 250),
		dis: u.col(245, 248, 252), brd: u.col(220, 228, 242),
	})
}

// ruleFilterButtonStyle 是规则列表「仅看启用 / 仅看禁用」按钮样式，
func (u *nativeUI) ruleFilterButtonStyle() widgets.ButtonStyle {
	return u.btnSty(btnCfg{
		sz: 14, wt: 600, pad: 8, ins: 10, gap: 7,
		txt: u.col(41, 52, 77), down: u.col(41, 52, 77), off: u.col(171, 183, 206),
		bg: u.col(255, 255, 255), hov: u.col(242, 246, 253), prs: u.col(232, 238, 250),
		dis: u.col(245, 248, 252), brd: u.col(220, 228, 242),
	})
}

// ruleFilterActiveStyle 是筛选按钮的激活态：仅看启用用浅绿、仅看禁用用浅灰。
func (u *nativeUI) ruleFilterEnabledActiveStyle() widgets.ButtonStyle {
	return u.btnSty(btnCfg{
		sz: 14, wt: 700, pad: 8, ins: 10, gap: 7,
		txt: u.col(22, 101, 52), down: u.col(22, 101, 52), off: u.col(132, 168, 142),
		bg: u.col(220, 252, 231), hov: u.col(209, 247, 223), prs: u.col(198, 242, 214),
		dis: u.col(220, 252, 231), brd: u.col(134, 239, 172),
	})
}

// ruleFilterDisabledActiveStyle 仅看禁用激活态：浅灰。
func (u *nativeUI) ruleFilterDisabledActiveStyle() widgets.ButtonStyle {
	return u.btnSty(btnCfg{
		sz: 14, wt: 700, pad: 8, ins: 10, gap: 7,
		txt: u.col(55, 65, 81), down: u.col(55, 65, 81), off: u.col(148, 163, 184),
		bg: u.col(229, 231, 235), hov: u.col(219, 222, 228), prs: u.col(209, 213, 219),
		dis: u.col(229, 231, 235), brd: u.col(203, 213, 225),
	})
}

// rulePrimaryButtonStyle 是规则列表「新增」主按钮，字号 14。
func (u *nativeUI) rulePrimaryButtonStyle() widgets.ButtonStyle {
	return u.btnSty(btnCfg{
		sz: 14, wt: 700, pad: 8, ins: 12, gap: 6,
		txt: u.col(255, 255, 255), down: u.col(255, 255, 255), off: u.col(225, 232, 243),
		bg: u.col(47, 104, 243), hov: u.col(38, 93, 228), prs: u.col(31, 78, 200),
		dis: u.col(160, 181, 235), brd: u.col(47, 104, 243),
	})
}

func (u *nativeUI) panelFocusButtonStyle() widgets.ButtonStyle {
	style := u.compactSoftButtonStyle()
	style.ImageSizeDP = 14
	style.PadDP = 8
	style.GapDP = 5
	return style
}

func (u *nativeUI) compactOutlineDangerStyle() widgets.ButtonStyle {
	return u.btnSty(btnCfg{
		sz: 12, wt: 600, pad: 7, ins: 10, gap: 6,
		txt: u.col(220, 38, 38), down: u.col(255, 255, 255), off: u.col(216, 158, 158),
		bg: u.col(255, 255, 255), hov: u.col(254, 242, 242), prs: u.col(220, 38, 38),
		dis: u.col(252, 243, 243), brd: u.col(252, 165, 165),
	})
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
		IndicatorStyle:  widgets.ChoiceIndicatorCheck,
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
		// 打勾列颜色：勾选用品牌蓝填充、白色标记；未勾选用浅灰描边。
		// 必须显式配置，否则 resolveStyle 走 scene 主题时拿到零值会被渲染成黑色。
		CheckColor:     u.col(47, 104, 243),
		CheckMarkColor: u.col(255, 255, 255),
		CheckBorder:    u.col(203, 213, 225),
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
