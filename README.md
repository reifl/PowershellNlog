# Graylog GELF PowerShell Module

A PowerShell module for structured logging to Graylog using the GELF 1.1 format (via UDP, TCP, or HTTPS).

## Features

- Send structured log messages to Graylog in GELF 1.1 format
- Support for all GELF standard fields and custom additional fields
- Multiple transport protocols: UDP (with optional GZIP compression and chunking), TCP, HTTPS
- Template-based message formatting (Serilog-style: `"User {user} logged in from {ip}"`)
- Structured logging with custom fields (automatically prefixed with `_`)
- Convenience functions for each log level (Send-GelfDebug, Send-GelfInfo, etc.)
- Pipeline integration for exception logging (`$_ | Send-GelfException`)
- Logging scope for correlation (shared fields across multiple messages)
- Duration measurement with automatic logging (`Measure-GelfDuration`)

## Log Levels (Syslog Severity)

| Level | Name | Description |
|-------|------|-------------|
| 0 | Emergency | System is unusable |
| 1 | Alert | Immediate action required |
| 2 | Critical | Critical conditions |
| 3 | Error | Error conditions |
| 4 | Warning | Warning conditions |
| 5 | Notice | Normal but significant condition |
| 6 | Informational | Informational messages |
| 7 | Debug | Debug-level messages |

## Integration into Your PowerShell Script

### 1. Import the Module

```powershell
# Import the module from the same directory
$modulePath = Join-Path $PSScriptRoot "GraylogGelf.psm1"
Import-Module $modulePath -Force
```

### 2. Configure the Graylog Server

```powershell
Set-GelfServer -Server "graylog.example.com" -Port 12201 -Protocol UDP
```

Optional parameters:
- `HostName` - Custom hostname for the log messages (default: `$env:COMPUTERNAME`)
- `DefaultFacility` - Custom facility name (default: "PowerShell")
- `CompressUdp` - Enable GZIP compression for UDP (default: true)
- `Timeout` - Connection timeout in ms (default: 5000)

```powershell
Set-GelfServer -Server "graylog.example.com" -Port 12201 -Protocol UDP `
    -HostName "MyApp-Server" -DefaultFacility "MyApplication" -CompressUdp
```

### 3. Start Logging

Use the level-specific functions for convenience:

```powershell
# Debug
Send-GelfDebug "Cache refresh started" @{
    items_count = 152
    duration_ms = 23
}

# Information
Send-GelfInfo "User 'admin' logged in successfully" @{
    user_id = "U-12345"
    source = "LDAP"
}

# Warning
Send-GelfWarning "Low disk space" @{
    drive = "C:"
    free_gb = 2.1
}

# Error
Send-GelfError "Database connection failed" @{
    retry_count = 3
}

# Critical
Send-GelfCritical "Database cluster unreachable" @{
    cluster = "prod-cluster-01"
}
```

For full control (Emergency, Alert, Notice levels), use `Send-GelfMessage`:

```powershell
Send-GelfMessage -ShortMessage "System failure" -Level Emergency -AdditionalFields @{
    impact = "complete_outage"
}
```

### 4. Message Templates (Serilog-Style)

Placeholders in the message template are automatically resolved from AdditionalFields:

```powershell
Send-GelfInfo "Order {order_id} completed" @{
    order_id = "ORD-2025-48291"
    customer_id = "C-1337"
    total_amount = 149.99
}
# Result: "Order ORD-2025-48291 completed"
```

The original template is preserved in Graylog as `_message_template` field for searching.

### 5. Exception Logging

```powershell
try {
    # Your code here
}
catch {
    $_ | Send-GelfException -Context @{
        operation = "Database operation"
    }
}
```

### 6. Logging with Correlation Scope

```powershell
$scope = New-GelfLoggingScope -Fields @{
    correlation_id = [guid]::NewGuid().ToString()
    request_path = "/api/orders"
}

Send-GelfScopedMessage -Scope $scope -ShortMessage "Request started"
Send-GelfScopedMessage -Scope $scope -ShortMessage "Database query" -AdditionalFields @{ query_ms = 45 }
Send-GelfScopedMessage -Scope $scope -ShortMessage "Request completed" -AdditionalFields @{ status = 200 }
```

### 7. Duration Measurement

```powershell
Measure-GelfDuration -Name "Data Import" -Fields @{ table = "orders" } -ScriptBlock {
    Import-Data -Table orders
}
```

## Available Functions

| Function | Description |
|----------|-------------|
| `Set-GelfServer` | Configure Graylog server connection |
| `Get-GelfServer` | Get current server configuration |
| `Send-GelfMessage` | Send a GELF message with full control |
| `Send-GelfDebug` | Send debug message (Level 7) |
| `Send-GelfInfo` | Send info message (Level 6) |
| `Send-GelfWarning` | Send warning message (Level 4) |
| `Send-GelfError` | Send error message (Level 3) |
| `Send-GelfCritical` | Send critical message (Level 2) |
| `Send-GelfException` | Log PowerShell exception via pipeline |
| `New-GelfLoggingScope` | Create a logging scope for correlation |
| `Send-GelfScopedMessage` | Send message with scope fields |
| `Measure-GelfDuration` | Measure and log scriptblock execution time |

## Requirements

- PowerShell 5.1 or higher
- .NET Framework 4.5+ (for GZIP compression)
