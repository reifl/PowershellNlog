<#
.SYNOPSIS
    Demo script: Integration of the GraylogGelf module into own PowerShell scripts.

.DESCRIPTION
    This script demonstrates how to integrate the GraylogGelf module into your own
    PowerShell scripts and use the typed functions (Send-GelfDebug, Send-GelfInfo, etc.)
    for logging.

.HOW TO USE
    1. Adapt Graylog server information in the .env file
    2. Use this script as a template
    3. Use the same integration logic in your own scripts

.MODULE FUNCTIONS
    Send-GelfDebug     - Debug message (Level 7)
    Send-GelfInfo      - Info message (Level 6)
    Send-GelfWarning   - Warning message (Level 4)
    Send-GelfError     - Error message (Level 3)
    Send-GelfCritical  - Critical message (Level 2)
    Send-GelfException - Exception logging via pipeline
    Send-GelfScopedMessage - Message with correlation scope

    For Emergency (Level 0), Alert (Level 1), Notice (Level 5) and full control:
    Send-GelfMessage -ShortMessage "..." -Level LevelName -AdditionalFields @{...}

    Additional functions:
    Set-GelfServer - Configure Graylog server
    Get-GelfServer - Display current configuration
    Measure-GelfDuration - Measure and log execution time
    New-GelfLoggingScope - Create correlation scope

.GELF LEVELS
    0 = Emergency (System is unusable)
    1 = Alert (Immediate action required)
    2 = Critical (Critical conditions)
    3 = Error (Error conditions)
    4 = Warning (Warning conditions)
    5 = Notice (Normal but significant condition)
    6 = Informational (Informational messages)
    7 = Debug (Debug-level messages)
#>

# ============================================================================
# 1. Import the module
# ============================================================================
# Import the module from the same directory
$modulePath = Join-Path $PSScriptRoot "GraylogGelf.psm1"
Import-Module $modulePath -Force

# ============================================================================
# 2. Load configuration from .env file
# ============================================================================
$envFilePath = Join-Path $PSScriptRoot ".env"
if (Test-Path $envFilePath) {
    Get-Content $envFilePath | ForEach-Object {
        if ($_ -match '^(.+?)=(.+)$') {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()
            if ($key -like 'GRAYLOG_*') {
                [Environment]::SetEnvironmentVariable($key, $value, [System.EnvironmentVariableTarget]::Process)
            }
        }
    }
    Write-Verbose "Configuration loaded from .env: $envFilePath"
}

# ============================================================================
# 3. Configure Graylog server
# ============================================================================
$server = $env:GRAYLOG_SERVER ?? 'localhost'
$port = [int]($env:GRAYLOG_PORT ?? '12201')
$protocol = $env:GRAYLOG_PROTOCOL ?? 'UDP'

Set-GelfServer -Server $server -Port $port -Protocol $protocol

# ============================================================================
# 4. Logging examples in your own scripts
# ============================================================================

Write-Host "=== Graylog Demo Logging ===" -ForegroundColor White
Write-Host ""

# --- DEBUG Level ---
# Send-GelfDebug is the typed function for Level 7
Send-GelfDebug "Cache refresh started with 152 entries" @{
    component = "CacheService"
    items_count = 152
    duration_ms = 23
}

# --- INFORMATION Level ---
# Send-GelfInfo is the typed function for Level 6
Send-GelfInfo "User 'admin' logged in successfully" @{
    user_id = "U-12345"
    source = "LDAP"
    ip_address = "192.168.1.42"
}

# --- NOTICE Level (using Send-GelfMessage as no typed function exists) ---
Send-GelfMessage -ShortMessage "New software version available" -Level Notice -AdditionalFields @{
    current_version = "2.5.1"
    available_version = "2.6.0"
    auto_update = $false
}

# --- WARNING Level ---
# Send-GelfWarning is the typed function for Level 4
Send-GelfWarning "Low disk space" @{
    drive = "C:"
    free_gb = 2.1
    threshold_percent = 85
    current_percent = 92
}

# --- ERROR Level ---
# Send-GelfError is the typed function for Level 3
try {
    # Simulated error
    throw "Database connection failed"
}
catch {
    Send-GelfError "User authentication failed" @{
        exception_type = $_.Exception.GetType().FullName
        exception_message = $_.Exception.Message
        retry_count = 3
        user_id = "U-12345"
    }
}

# --- CRITICAL Level ---
# Send-GelfCritical is the typed function for Level 2
Send-GelfCritical "Database cluster unreachable" @{
    cluster = "prod-cluster-01"
    node = "node-03"
    connection_timeout_ms = 30000
    affected_services = @("API", "WebUI")
}

# --- ALERT Level (using Send-GelfMessage as no typed function exists) ---
Send-GelfMessage -ShortMessage "Immediate intervention required" -Level Alert -AdditionalFields @{
    severity = "high"
    affected_systems = @("Auth-Service", "User-DB")
    recommended_action = "Check network connectivity"
}

# --- EMERGENCY Level (using Send-GelfMessage as no typed function exists) ---
Send-GelfMessage -ShortMessage "System completely down" -Level Emergency -AdditionalFields @{
    impact = "complete_outage"
    estimated_recovery_time = "2h"
    escalation_needed = $true
}

# ============================================================================
# 5. Structured logging with message templates (Serilog-style)
# ============================================================================
Write-Host ""
Write-Host "=== Structured logging with templates ===" -ForegroundColor Cyan
Write-Host ""

# Placeholders in the template are automatically resolved from AdditionalFields
Send-GelfInfo "Order {order_id} completed" @{
    order_id = "ORD-2025-48291"
    customer_id = "C-1337"
    total_amount = 149.99
    currency = "EUR"
    items_count = 3
    processing_ms = 234
}

# ============================================================================
# 6. Logging with exception (pipeline integration)
# ============================================================================
Write-Host ""
Write-Host "=== Logging with exception ===" -ForegroundColor Cyan
Write-Host ""

try {
    # Simulated error
    Get-Item "C:\nix\da" -ErrorAction Stop
}
catch {
    # Log exception directly via pipeline
    $_ | Send-GelfException -Context @{
        operation = "File read error"
        script_version = "1.0.0"
    }
}

# ============================================================================
# 7. Logging with destructuring (objects as JSON)
# ============================================================================
Write-Host ""
Write-Host "=== Logging with destructuring ===" -ForegroundColor Cyan
Write-Host ""

# With {@} an object is serialized as JSON
Send-GelfInfo "Processing completed: {@result}" @{
    result = [pscustomobject]@{
        processed = 1523
        failed = 7
        duration_seconds = 45.23
        details = @{
            step1 = "Validation"
            step2 = "Transformation"
            step3 = "Storage"
        }
    }
}

# ============================================================================
# 8. Logging with correlation scope
# ============================================================================
Write-Host ""
Write-Host "=== Logging with correlation scope ===" -ForegroundColor Cyan
Write-Host ""

# Create logging scope - all messages in the scope share the same fields
$scope = New-GelfLoggingScope -Fields @{
    correlation_id = [guid]::NewGuid().ToString()
    request_path = "/api/orders"
    user_id = "U-12345"
}

# Messages with scope fields
Send-GelfScopedMessage -Scope $scope -ShortMessage "Request started"
Send-GelfScopedMessage -Scope $scope -ShortMessage "Database query" -AdditionalFields @{ query_ms = 45 }
Send-GelfScopedMessage -Scope $scope -ShortMessage "Request completed" -AdditionalFields @{ status = 200 }

# ============================================================================
# 9. Duration measurement
# ============================================================================
Write-Host ""
Write-Host "=== Duration measurement ===" -ForegroundColor Cyan
Write-Host ""

# Measure execution duration with automatic logging
Measure-GelfDuration -Name "Cache refresh" -Fields @{ cache_size = 152 } -ScriptBlock {
    # Simulated slow operation
    Start-Sleep -Milliseconds 500
}

# ============================================================================
# 10. Display current configuration
# ============================================================================
Write-Host ""
Write-Host "=== Current server configuration ===" -ForegroundColor Cyan
Write-Host ""
Get-GelfServer | Format-List
