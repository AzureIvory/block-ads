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
