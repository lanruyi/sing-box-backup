---
icon: material/new-box
---

# 内存泄漏报告器

!!! question "自 sing-box 1.13.0 起"

### 结构

```json
{
  "type": "memory-leak-reporter",
  "tag": "memory-leak-reporter",

  "directory": "",
  "interval": "",
  "growth_rate_threshold": 0,
  "growth_rate_window": "",
  "consecutive_growth_count": 0,
  "absolute_threshold": "",
  "export_interval": "",
  "max_export_count": 0,
  "exec_shell": "",
  "exit_after_found": false,
  "exit_status": 1
}
```

### 字段

#### directory

==必填==

导出 pprof zip 文件的目录。

#### interval

内存采样间隔。

默认使用 `5m`。

#### growth_rate_threshold

当内存在 `growth_rate_window` 时间窗口内增长超过此百分比时触发。例如 `0.5` 表示 50%。

默认禁用。

#### growth_rate_window

增长率计算的时间窗口。

默认使用 `30m`。

#### consecutive_growth_count

当内存连续 N 次采样都在增长时触发。

默认禁用。

#### absolute_threshold

当内存超过此值时触发。例如 `500MB`。

默认禁用。

#### export_interval

检测到泄漏后两次导出之间的最小间隔。

默认使用 `1h`。

#### max_export_count

最大导出次数。

默认无限制。

#### exec_shell

导出后执行的 Shell 命令。支持模板参数 `{{ .file }}` 表示导出的 zip 文件路径。

默认为空。

#### exit_after_found

检测到内存泄漏并导出后退出程序。

默认禁用。

#### exit_status

当 `exit_after_found` 启用时的退出状态码。

默认使用 `1`。
