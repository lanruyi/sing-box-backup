package option

import (
	"github.com/sagernet/sing/common/byteformats"
	"github.com/sagernet/sing/common/json/badoption"
)

type MemoryLeakReporterServiceOptions struct {
	Directory              string                   `json:"directory,omitempty"`
	Interval               badoption.Duration       `json:"interval,omitempty"`
	GrowthRateThreshold    float64                  `json:"growth_rate_threshold,omitempty"`
	GrowthRateWindow       badoption.Duration       `json:"growth_rate_window,omitempty"`
	ConsecutiveGrowthCount int                      `json:"consecutive_growth_count,omitempty"`
	AbsoluteThreshold      *byteformats.MemoryBytes `json:"absolute_threshold,omitempty"`
	ExportInterval         badoption.Duration       `json:"export_interval,omitempty"`
	MaxExportCount         int                      `json:"max_export_count,omitempty"`
	ExecShell              string                   `json:"exec_shell,omitempty"`
	ExitAfterFound         bool                     `json:"exit_after_found,omitempty"`
	ExitStatus             int                      `json:"exit_status,omitempty"`
}
