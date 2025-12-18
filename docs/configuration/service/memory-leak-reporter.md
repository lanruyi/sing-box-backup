---
icon: material/new-box
---

# Memory Leak Reporter

!!! question "Since sing-box 1.13.0"

### Structure

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

### Fields

#### directory

==Required==

Directory to export pprof zip files.

#### interval

Memory sampling interval.

`5m` will be used by default.

#### growth_rate_threshold

Trigger when memory grows by this percentage within the `growth_rate_window`. E.g., `0.5` means 50%.

Disabled by default.

#### growth_rate_window

Time window for growth rate calculation.

`30m` will be used by default.

#### consecutive_growth_count

Trigger when memory grows for N consecutive samples.

Disabled by default.

#### absolute_threshold

Trigger when memory exceeds this value. E.g., `500MB`.

Disabled by default.

#### export_interval

Minimum interval between exports after detection.

`1h` will be used by default.

#### max_export_count

Maximum number of exports.

Unlimited by default.

#### exec_shell

Shell command to execute after export. Supports template parameter `{{ .file }}` for the exported zip file path.

Empty by default.

#### exit_after_found

Exit the program after memory leak is detected and exported.

Disabled by default.

#### exit_status

Exit status code when `exit_after_found` is enabled.

`1` will be used by default.
