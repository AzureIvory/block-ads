//go:build windows

package main

import (
	"github.com/AzureIvory/winui/widgets"
)

func (u *nativeUI) primaryButtonStyle() widgets.ButtonStyle {
	return widgets.ButtonStyle{
		Font:         widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 15, Weight: 700},
		TextAlign:    widgets.AlignCenter,
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
		TextAlign:    widgets.AlignCenter,
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
		TextAlign:    widgets.AlignCenter,
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
		TextAlign:    widgets.AlignCenter,
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
			TextAlign:    widgets.AlignCenter,
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
		TextAlign:    widgets.AlignCenter,
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
		TextAlign:    widgets.AlignCenter,
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
		TextAlign:    widgets.AlignCenter,
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
		TextAlign:    widgets.AlignCenter,
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
		TextAlign:    widgets.AlignCenter,
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
		TextAlign:    widgets.AlignCenter,
		TextColor:    u.col(255, 255, 255),
		DownText:     u.col(255, 255, 255),
		DisabledText: u.col(255, 255, 255),
		Background:   u.col(255, 255, 255),
		Hover:        u.col(255, 255, 255),
		Pressed:      u.col(255, 255, 255),
		Disabled:     u.col(255, 255, 255),
		Border:       u.col(255, 255, 255),
		CornerRadius: 0,
		ImageSizeDP:  72,
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
