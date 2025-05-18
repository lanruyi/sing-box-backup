---
icon: material/new-box
---

!!! question "Since sing-box 1.12.0"

# Resolved

Resolved service is a fake systemd-resolved DBUS service to receive DNS settings from other programs and provide DNS resolution.

See also: [Resolved DNS server](/configuration/dns/server/resolved/)

### Structure

```json
{
  "type": "resolved",
  
  ... // Listen Fields
}
```

### Listen Fields

See [Listen Fields](/configuration/shared/listen/) for details.

### Fields

#### listen

==Required==

Listen address.

`127.0.0.53` will be used by default.

#### listen_port

==Required==

Listen port.

`53` will be used by default.
