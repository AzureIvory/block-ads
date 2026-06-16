//go:build windows

package main

const (
	panelFocusNone  = ""
	panelFocusRules = "rules"
	panelFocusLogs  = "logs"
)

type contentLayout struct {
	RulesH       int32
	LogsY        int32
	LogsH        int32
	ShowLogs     bool
	ShowRuleBody bool
	ShowLogBody  bool
}

// planContentLayout 统一计算规则区和日志区高度，避免局部状态刷新后互相覆盖。
func planContentLayout(topY, contentBottom, gap, collapsedH, oneLogH int32, logCount int, focus string) contentLayout {
	totalH := contentBottom - topY
	if totalH < collapsedH {
		totalH = collapsedH
	}

	switch focus {
	case panelFocusRules:
		return contentLayout{
			RulesH:       totalH,
			ShowRuleBody: true,
		}
	case panelFocusLogs:
		logsH := totalH - collapsedH - gap
		if logsH < collapsedH {
			logsH = collapsedH
		}
		return contentLayout{
			RulesH:       collapsedH,
			LogsY:        topY + collapsedH + gap,
			LogsH:        logsH,
			ShowLogs:     true,
			ShowRuleBody: false,
			ShowLogBody:  true,
		}
	}

	if logCount <= 0 {
		rulesH := totalH - collapsedH - gap
		if rulesH < collapsedH {
			rulesH = collapsedH
		}
		return contentLayout{
			RulesH:       rulesH,
			LogsY:        topY + rulesH + gap,
			LogsH:        collapsedH,
			ShowLogs:     true,
			ShowRuleBody: true,
		}
	}

	if logCount == 1 {
		logsH := oneLogH
		maxLogsH := totalH - collapsedH - gap
		if logsH > maxLogsH {
			logsH = maxLogsH
		}
		if logsH < collapsedH {
			logsH = collapsedH
		}
		rulesH := totalH - logsH - gap
		if rulesH < collapsedH {
			rulesH = collapsedH
		}
		return contentLayout{
			RulesH:       rulesH,
			LogsY:        topY + rulesH + gap,
			LogsH:        logsH,
			ShowLogs:     true,
			ShowRuleBody: true,
			ShowLogBody:  true,
		}
	}

	bodyH := totalH - gap
	rulesH := bodyH / 2
	logsH := bodyH - rulesH
	if rulesH < collapsedH {
		rulesH = collapsedH
	}
	if logsH < collapsedH {
		logsH = collapsedH
	}
	return contentLayout{
		RulesH:       rulesH,
		LogsY:        topY + rulesH + gap,
		LogsH:        logsH,
		ShowLogs:     true,
		ShowRuleBody: true,
		ShowLogBody:  true,
	}
}
