#Requires -Version 5.1
<#
.SYNOPSIS
    PowerShell module for structured logging to Graylog in GELF 1.1 format.

.DESCRIPTION
    Provides functions to send structured log messages to a Graylog server
    via UDP, TCP, or HTTPS (GELF Input).
    Supports all GELF 1.1 fields as well as custom additional fields.

.NOTES
    GELF Spec: https://go2docs.graylog.org/current/getting_in_log_data/gelf.html
#>

# ============================================================================
# Configuration
# ============================================================================

$Script:GelfConfig = @{
    Server       = $null
    Port         = 12201
    Protocol     = 'UDP'        # UDP | TCP | HTTPS
    HostName     = $env:COMPUTERNAME
    MaxChunkSize = 8192         # UDP chunk size (WAN: 1420, LAN: 8192)
    DefaultFacility = 'PowerShell'
    CompressUdp  = $true        # GZIP compression for UDP
    TcpNullTerminate = $true    # Null-byte termination for TCP (Graylog standard)
    HttpsIgnoreCert  = $false   # Allow self-signed certificates
    Timeout      = 5000         # Timeout in ms
}

# Syslog Severity Levels
enum GelfLevel {
    Emergency     = 0
    Alert         = 1
    Critical      = 2
    Error         = 3
    Warning       = 4
    Notice        = 5
    Informational = 6
    Debug         = 7
}

# ============================================================================
# Konfigurationsfunktionen
# ============================================================================

function Set-GelfServer {
    <#
    .SYNOPSIS
        Configures the connection to the Graylog server.
    .EXAMPLE
        Set-GelfServer -Server "graylog.example.com" -Port 12201 -Protocol UDP
    .EXAMPLE
        Set-GelfServer -Server "graylog.example.com" -Port 12201 -Protocol HTTPS -IgnoreCertificateErrors
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Server,

        [ValidateRange(1, 65535)]
        [int]$Port = 12201,

        [ValidateSet('UDP', 'TCP', 'HTTPS')]
        [string]$Protocol = 'UDP',

        [string]$HostName = $env:COMPUTERNAME,

        [string]$DefaultFacility = 'PowerShell',

        [switch]$CompressUdp,

        [switch]$IgnoreCertificateErrors,

        [ValidateRange(100, 30000)]
        [int]$Timeout = 5000
    )

    $Script:GelfConfig.Server       = $Server
    $Script:GelfConfig.Port         = $Port
    $Script:GelfConfig.Protocol     = $Protocol.ToUpper()
    $Script:GelfConfig.HostName     = $HostName
    $Script:GelfConfig.DefaultFacility = $DefaultFacility
    $Script:GelfConfig.Timeout      = $Timeout

    if ($PSBoundParameters.ContainsKey('CompressUdp')) {
        $Script:GelfConfig.CompressUdp = $CompressUdp.IsPresent
    }
    if ($IgnoreCertificateErrors) {
        $Script:GelfConfig.HttpsIgnoreCert = $true
    }

    Write-Verbose "GELF server configured: $Protocol`://${Server}:${Port}"
}

function Get-GelfServer {
    <#
    .SYNOPSIS
        Displays the current GELF server configuration.
    #>
    [CmdletBinding()]
    param()
    [PSCustomObject]$Script:GelfConfig
}

# ============================================================================
# Message Template Engine (Serilog-Style)
# ============================================================================

function Resolve-GelfMessageTemplate {
    <#
    .SYNOPSIS
        Resolves placeholders in message templates (Serilog/NLog-style).
    .DESCRIPTION
        Replaces {PropertyName}-placeholders in the template with corresponding
        values from the properties hashtable. Supports:
        - Simple placeholders:    "Service {service} started"
        - Format strings:         "Duration: {elapsed:F2}ms"
        - Destructuring:           "Object {@obj}"  (ConvertTo-Json)
        - Stringification:         "Value {$val}"    (ToString)
        - Escaped braces:          "JSON: {{key}}"  → "JSON: {key}"

        Unresolved placeholders remain as {name}.
    .EXAMPLE
        Resolve-GelfMessageTemplate -Template "User {user} logged in from {ip}" -Properties @{ user = "admin"; ip = "10.0.0.1" }
        # → "User admin logged in from 10.0.0.1"
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Template,

        [hashtable]$Properties
    )

    if (-not $Properties -or $Properties.Count -eq 0) {
        return $Template
    }

    # Temporarily store escaped braces
    $result = $Template.Replace('{{', "`0LBRACE`0").Replace('}}', "`0RBRACE`0")

    # Regex: {[@$]?PropertyName[:FormatString]}
    $result = [regex]::Replace($result, '\{([@\$]?)(\w+)(?::([^}]+))?\}', {
        param($match)

        $prefix    = $match.Groups[1].Value   # @, $, or empty
        $name      = $match.Groups[2].Value   # Field name
        $format    = $match.Groups[3].Value   # Optional format string

        # Find field (case-insensitive)
        $value = $null
        $found = $false
        foreach ($key in $Properties.Keys) {
            if ($key -eq $name) {
                $value = $Properties[$key]
                $found = $true
                break
            }
        }

        if (-not $found) {
            # Leave placeholder unchanged
            return $match.Value
        }

        # Format value
        switch ($prefix) {
            '@' {
                # Destructuring: Serialize object as JSON
                if ($null -eq $value) { return 'null' }
                try   { return ($value | ConvertTo-Json -Compress -Depth 3) }
                catch { return "$value" }
            }
            '$' {
                # Stringification: Explicit ToString()
                if ($null -eq $value) { return '' }
                return "$value"
            }
            default {
                if ($null -eq $value) { return '' }
                # Apply format string if present
                if ($format) {
                    try   { return ("{0:$format}" -f $value) }
                    catch { return "$value" }
                }
                return "$value"
            }
        }
    })

    # Escaped Braces wiederherstellen
    $result = $result.Replace("`0LBRACE`0", '{').Replace("`0RBRACE`0", '}')

    return $result
}

# ============================================================================
# Core function: Create GELF message
# ============================================================================

function New-GelfMessage {
    <#
    .SYNOPSIS
        Creates a GELF 1.1 compliant message object.
    .DESCRIPTION
        Builds a GELF message with required fields and optional
        custom additional fields (structured logging).
    .EXAMPLE
        New-GelfMessage -ShortMessage "User logged in" -Level Informational -AdditionalFields @{
            _user_id    = "U-12345"
            _session_id = "S-99887"
            _ip_address = "192.168.1.42"
        }
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ShortMessage,

        [string]$FullMessage,

        [GelfLevel]$Level = [GelfLevel]::Informational,

        [string]$Facility,

        [hashtable]$AdditionalFields,

        [double]$Timestamp
    )

    # Unix timestamp with microsecond precision
    if (-not $PSBoundParameters.ContainsKey('Timestamp')) {
        $Timestamp = [math]::Round(
            (Get-Date).ToUniversalTime().Subtract(
                [datetime]'1970-01-01T00:00:00Z'
            ).TotalSeconds, 6
        )
    }

    # Resolve message template (Serilog-style)
    $resolvedShort = $ShortMessage
    $resolvedFull  = $FullMessage
    $hasTemplate   = $false

    if ($AdditionalFields -and $ShortMessage -match '\{[\w@\$]') {
        $hasTemplate   = $true
        $resolvedShort = Resolve-GelfMessageTemplate -Template $ShortMessage -Properties $AdditionalFields
    }
    if ($AdditionalFields -and $FullMessage -and $FullMessage -match '\{[\w@\$]') {
        $hasTemplate   = $true
        $resolvedFull  = Resolve-GelfMessageTemplate -Template $FullMessage -Properties $AdditionalFields
    }

    $message = [ordered]@{
        version       = '1.0'
        host          = $Script:GelfConfig.HostName
        short_message = $resolvedShort
        timestamp     = $Timestamp
        level         = [int]$Level
    }

    # Store original template as additional field (like Serilog MessageTemplate)
    if ($hasTemplate) {
        $message['_message_template'] = $ShortMessage
    }

    if ($resolvedFull) {
        $message['full_message'] = $resolvedFull
    }

    if ($Facility) {
        $message['_facility'] = $Facility
    }
    elseif ($Script:GelfConfig.DefaultFacility) {
        $message['_facility'] = $Script:GelfConfig.DefaultFacility
    }

    # Additional fields (must start with underscore, 'id' is reserved)
    if ($AdditionalFields) {
        foreach ($key in $AdditionalFields.Keys) {
            $fieldName = $key
            # Automatically prepend underscore if missing
            if (-not $fieldName.StartsWith('_')) {
                $fieldName = "_$fieldName"
            }
            # GELF reserves '_id' - rename
            if ($fieldName -eq '_id') {
                Write-Warning "Field '_id' is reserved in GELF. Renaming to '_record_id'."
                $fieldName = '_record_id'
            }
            $message[$fieldName] = $AdditionalFields[$key]
        }
    }

    return $message
}

# ============================================================================
# Transport functions
# ============================================================================

function Send-GelfMessageUdp {
    <#
    .SYNOPSIS
        Sends a GELF message via UDP (with optional chunking & GZIP).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [byte[]]$Payload,

        [string]$Server = $Script:GelfConfig.Server,
        [int]$Port = $Script:GelfConfig.Port,
        [bool]$Compress = $Script:GelfConfig.CompressUdp,
        [int]$MaxChunkSize = $Script:GelfConfig.MaxChunkSize
    )

    $data = $Payload

    # Optional: GZIP compression
    if ($Compress) {
        $data = Compress-GelfData -Data $Payload
    }

    $udpClient = $null
    try {
        $udpClient = New-Object System.Net.Sockets.UdpClient

        # Chunking required?
        if ($data.Length -gt $MaxChunkSize) {
            Send-GelfChunked -UdpClient $udpClient -Data $data `
                -Server $Server -Port $Port -MaxChunkSize $MaxChunkSize
        }
        else {
            [void]$udpClient.Send($data, $data.Length, $Server, $Port)
        }
    }
    finally {
        if ($udpClient) { $udpClient.Close() }
    }
}

function Send-GelfChunked {
    <#
    .SYNOPSIS
        Sends a large GELF message as UDP chunks (GELF chunking protocol).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Net.Sockets.UdpClient]$UdpClient,

        [Parameter(Mandatory)]
        [byte[]]$Data,

        [string]$Server,
        [int]$Port,
        [int]$MaxChunkSize = 8192
    )

    # 12 bytes header per chunk
    $chunkHeaderSize = 12
    $chunkDataSize = $MaxChunkSize - $chunkHeaderSize
    $chunkCount = [math]::Ceiling($Data.Length / $chunkDataSize)

    if ($chunkCount -gt 128) {
        throw "GELF message too large: $chunkCount chunks required (max 128)."
    }

    # Message ID: 8 bytes (random)
    $messageId = [byte[]]::new(8)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($messageId)

    # Chunked magic bytes: 0x1e 0x0f
    $magic = [byte[]]@(0x1e, 0x0f)

    for ($i = 0; $i -lt $chunkCount; $i++) {
        $offset = $i * $chunkDataSize
        $length = [math]::Min($chunkDataSize, $Data.Length - $offset)

        $chunk = [byte[]]::new($chunkHeaderSize + $length)

        # Header: Magic(2) + MessageId(8) + SeqNum(1) + SeqCount(1)
        [Array]::Copy($magic, 0, $chunk, 0, 2)
        [Array]::Copy($messageId, 0, $chunk, 2, 8)
        $chunk[10] = [byte]$i
        $chunk[11] = [byte]$chunkCount

        # Data
        [Array]::Copy($Data, $offset, $chunk, $chunkHeaderSize, $length)

        [void]$UdpClient.Send($chunk, $chunk.Length, $Server, $Port)
    }

    Write-Verbose "GELF message sent in $chunkCount chunks."
}

function Send-GelfMessageTcp {
    <#
    .SYNOPSIS
        Sends a GELF message via TCP (null-byte terminated).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [byte[]]$Payload,

        [string]$Server = $Script:GelfConfig.Server,
        [int]$Port = $Script:GelfConfig.Port,
        [bool]$NullTerminate = $Script:GelfConfig.TcpNullTerminate,
        [int]$Timeout = $Script:GelfConfig.Timeout
    )

    $tcpClient = $null
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.SendTimeout = $Timeout
        $tcpClient.ConnectAsync($Server, $Port).Wait($Timeout) | Out-Null

        if (-not $tcpClient.Connected) {
            throw "TCP connection to ${Server}:${Port} failed."
        }

        $stream = $tcpClient.GetStream()

        # Append null-byte at the end (Graylog standard for TCP GELF)
        if ($NullTerminate) {
            $sendData = [byte[]]::new($Payload.Length + 1)
            [Array]::Copy($Payload, $sendData, $Payload.Length)
            $sendData[$sendData.Length - 1] = 0
        }
        else {
            $sendData = $Payload
        }

        $stream.Write($sendData, 0, $sendData.Length)
        $stream.Flush()
    }
    finally {
        if ($tcpClient) { $tcpClient.Close() }
    }
}

function Send-GelfMessageHttps {
    <#
    .SYNOPSIS
        Sends a GELF message via HTTPS POST.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$JsonPayload,

        [string]$Server = $Script:GelfConfig.Server,
        [int]$Port = $Script:GelfConfig.Port,
        [bool]$IgnoreCert = $Script:GelfConfig.HttpsIgnoreCert,
        [int]$Timeout = $Script:GelfConfig.Timeout
    )

    $uri = "https://${Server}:${Port}/gelf"

    $params = @{
        Uri         = $uri
        Method      = 'POST'
        Body        = $JsonPayload
        ContentType = 'application/json'
        TimeoutSec  = [math]::Ceiling($Timeout / 1000)
    }

    if ($IgnoreCert -and $PSVersionTable.PSVersion.Major -ge 7) {
        $params['SkipCertificateCheck'] = $true
    }
    elseif ($IgnoreCert) {
        # PowerShell 5.1 Workaround
        if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
            Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint sp, X509Certificate cert,
        WebRequest req, int problem) { return true; }
}
"@
        }
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    }

    Invoke-RestMethod @params
}

# ============================================================================
# Helper functions
# ============================================================================

function Compress-GelfData {
    [CmdletBinding()]
    param([byte[]]$Data)

    $ms = New-Object System.IO.MemoryStream
    $gz = New-Object System.IO.Compression.GZipStream($ms,
        [System.IO.Compression.CompressionMode]::Compress, $true)
    $gz.Write($Data, 0, $Data.Length)
    $gz.Close()
    $result = $ms.ToArray()
    $ms.Close()
    return $result
}

# ============================================================================
# Main function: Send message
# ============================================================================

function Send-GelfMessage {
    <#
    .SYNOPSIS
        Sends a structured log message in GELF 1.1 format to Graylog.
    .DESCRIPTION
        Creates and sends a GELF message over the configured protocol.
        Supports all GELF standard fields as well as any custom additional
        fields for structured logging.

    .PARAMETER ShortMessage
        Required. Short description of the log message.

    .PARAMETER FullMessage
        Optional detailed description (e.g., stack trace).

    .PARAMETER Level
        Syslog severity level (0=Emergency ... 7=Debug). Default: Informational.

    .PARAMETER AdditionalFields
        Hashtable with custom fields for structured logging.
        Underscore prefix is automatically added.

    .EXAMPLE
        # Simple message
        Send-GelfMessage -ShortMessage "Service started"

    .EXAMPLE
        # Structured logging with additional fields
        Send-GelfMessage -ShortMessage "Order completed" -Level Informational -AdditionalFields @{
            order_id      = "ORD-2025-48291"
            customer_id   = "C-1337"
            total_amount  = 149.99
            currency      = "EUR"
            payment_method = "Credit card"
            items_count   = 3
            processing_ms = 234
        }

    .EXAMPLE
        # Error with stack trace
        try { Get-Item "C:\nix\da" -ErrorAction Stop }
        catch {
            Send-GelfMessage -ShortMessage "File not found" `
                -FullMessage $_.Exception.ToString() `
                -Level Error -AdditionalFields @{
                    exception_type = $_.Exception.GetType().Name
                    script_name    = $MyInvocation.ScriptName
                    line_number    = $_.InvocationInfo.ScriptLineNumber
                }
        }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$ShortMessage,

        [string]$FullMessage,

        [GelfLevel]$Level = [GelfLevel]::Informational,

        [string]$Facility,

        [hashtable]$AdditionalFields,

        [ValidateSet('UDP', 'TCP', 'HTTPS')]
        [string]$Protocol
    )

    # Verify configuration
    if (-not $Script:GelfConfig.Server) {
        throw "No GELF server configured. Call Set-GelfServer first."
    }

    # Build message
    $msgParams = @{ ShortMessage = $ShortMessage; Level = $Level }
    if ($FullMessage)       { $msgParams['FullMessage'] = $FullMessage }
    if ($Facility)          { $msgParams['Facility'] = $Facility }
    if ($AdditionalFields)  { $msgParams['AdditionalFields'] = $AdditionalFields }

    $gelfMessage = New-GelfMessage @msgParams
    $json = $gelfMessage | ConvertTo-Json -Compress -Depth 10

    Write-Verbose "GELF sending: $json"

    # Determine protocol
    $proto = if ($Protocol) { $Protocol.ToUpper() } else { $Script:GelfConfig.Protocol }

    switch ($proto) {
        'UDP' {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
            Send-GelfMessageUdp -Payload $bytes
        }
        'TCP' {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
            Send-GelfMessageTcp -Payload $bytes
        }
        'HTTPS' {
            Send-GelfMessageHttps -JsonPayload $json
        }
    }
}

# ============================================================================
# Convenience functions (log-level shortcuts)
# ============================================================================

function Send-GelfDebug {
    <#
    .SYNOPSIS
        Sends a debug message (Level 7).
    .EXAMPLE
        Send-GelfDebug "Variable X = 42" @{ variable = "X"; value = 42 }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Message,

        [Parameter(Position = 1)]
        [hashtable]$Fields
    )
    Send-GelfMessage -ShortMessage $Message -Level Debug -AdditionalFields $Fields
}

function Send-GelfInfo {
    <#
    .SYNOPSIS
        Sends an info message (Level 6).
    .EXAMPLE
        Send-GelfInfo "User logged in" @{ user = "admin"; source = "LDAP" }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Message,

        [Parameter(Position = 1)]
        [hashtable]$Fields
    )
    Send-GelfMessage -ShortMessage $Message -Level Informational -AdditionalFields $Fields
}

function Send-GelfWarning {
    <#
    .SYNOPSIS
        Sends a warning message (Level 4).
    .EXAMPLE
        Send-GelfWarning "Low disk space" @{ drive = "C:"; free_gb = 2.1 }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Message,

        [Parameter(Position = 1)]
        [hashtable]$Fields
    )
    Send-GelfMessage -ShortMessage $Message -Level Warning -AdditionalFields $Fields
}

function Send-GelfError {
    <#
    .SYNOPSIS
        Sends an error message (Level 3).
    .EXAMPLE
        Send-GelfError "Database connection failed" @{ db = "ProdDB"; retry = 3 }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Message,

        [Parameter(Position = 1)]
        [hashtable]$Fields
    )
    Send-GelfMessage -ShortMessage $Message -Level Error -AdditionalFields $Fields
}

function Send-GelfCritical {
    <#
    .SYNOPSIS
        Sends a critical message (Level 2).
    .EXAMPLE
        Send-GelfCritical "Cluster node failed" @{ node = "node-03"; cluster = "prod" }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Message,

        [Parameter(Position = 1)]
        [hashtable]$Fields
    )
    Send-GelfMessage -ShortMessage $Message -Level Critical -AdditionalFields $Fields
}

# ============================================================================
# Pipeline integration: Log exceptions directly
# ============================================================================

function Send-GelfException {
    <#
    .SYNOPSIS
        Logs a PowerShell exception structured to Graylog.
    .EXAMPLE
        try { 1/0 } catch { $_ | Send-GelfException -Context @{ operation = "Calculation" } }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        [GelfLevel]$Level = [GelfLevel]::Error,

        [hashtable]$Context
    )

    process {
        $fields = [ordered]@{
            exception_type    = $ErrorRecord.Exception.GetType().FullName
            exception_message = $ErrorRecord.Exception.Message
            error_category    = $ErrorRecord.CategoryInfo.Category.ToString()
            target_object     = "$($ErrorRecord.TargetObject)"
            script_name       = "$($ErrorRecord.InvocationInfo.ScriptName)"
            line_number       = $ErrorRecord.InvocationInfo.ScriptLineNumber
            command_name      = "$($ErrorRecord.InvocationInfo.MyCommand)"
        }

        if ($Context) {
            foreach ($key in $Context.Keys) {
                $fields[$key] = $Context[$key]
            }
        }

        Send-GelfMessage `
            -ShortMessage $ErrorRecord.Exception.Message `
            -FullMessage $ErrorRecord.Exception.ToString() `
            -Level $Level `
            -AdditionalFields $fields
    }
}

# ============================================================================
# Scoped logging context (correlation)
# ============================================================================

function New-GelfLoggingScope {
    <#
    .SYNOPSIS
        Creates a logging context with shared fields for multiple messages.
    .DESCRIPTION
        Useful for request tracing or correlation: All messages within a scope
        share the defined fields (e.g., correlation_id).
    .EXAMPLE
        $scope = New-GelfLoggingScope -Fields @{
            correlation_id = [guid]::NewGuid().ToString()
            request_path   = "/api/orders"
            user_id        = "U-42"
        }

        # All messages inherit the scope fields
        Send-GelfScopedMessage -Scope $scope -ShortMessage "Request started"
        Send-GelfScopedMessage -Scope $scope -ShortMessage "DB query" -AdditionalFields @{ query_ms = 45 }
        Send-GelfScopedMessage -Scope $scope -ShortMessage "Request completed" -AdditionalFields @{ status = 200 }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Fields
    )

    return [PSCustomObject]@{
        PSTypeName = 'GelfLoggingScope'
        Fields     = $Fields
        CreatedAt  = [datetime]::UtcNow
    }
}

function Send-GelfScopedMessage {
    <#
    .SYNOPSIS
        Sends a message with the fields from a logging scope.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Scope,

        [Parameter(Mandatory)]
        [string]$ShortMessage,

        [string]$FullMessage,

        [GelfLevel]$Level = [GelfLevel]::Informational,

        [hashtable]$AdditionalFields
    )

    # Merge scope fields with message fields
    $merged = @{}
    foreach ($key in $Scope.Fields.Keys) { $merged[$key] = $Scope.Fields[$key] }
    if ($AdditionalFields) {
        foreach ($key in $AdditionalFields.Keys) { $merged[$key] = $AdditionalFields[$key] }
    }

    $params = @{
        ShortMessage     = $ShortMessage
        Level            = $Level
        AdditionalFields = $merged
    }
    if ($FullMessage) { $params['FullMessage'] = $FullMessage }

    Send-GelfMessage @params
}

# ============================================================================
# Metrics / structured logging helpers
# ============================================================================

function Measure-GelfDuration {
    <#
    .SYNOPSIS
        Measures the execution duration of a scriptblock and logs the result.
    .EXAMPLE
        Measure-GelfDuration -Name "DB import" -Fields @{ table = "orders" } -ScriptBlock {
            Import-Data -Table orders
        }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [hashtable]$Fields,

        [GelfLevel]$Level = [GelfLevel]::Informational
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $error_occurred = $false

    try {
        & $ScriptBlock
    }
    catch {
        $error_occurred = $true
        $_ | Send-GelfException -Context ($Fields + @{ operation = $Name })
        throw
    }
    finally {
        $sw.Stop()
        $allFields = @{ duration_ms = $sw.ElapsedMilliseconds; operation = $Name; success = (-not $error_occurred) }
        if ($Fields) {
            foreach ($key in $Fields.Keys) { $allFields[$key] = $Fields[$key] }
        }
        Send-GelfMessage -ShortMessage "$Name completed (${($sw.ElapsedMilliseconds)}ms)" `
            -Level $Level -AdditionalFields $allFields
    }
}

# ============================================================================
# Module export
# ============================================================================

Export-ModuleMember -Function @(
    'Set-GelfServer'
    'Get-GelfServer'
    'New-GelfMessage'
    'Resolve-GelfMessageTemplate'
    'Send-GelfMessage'
    'Send-GelfDebug'
    'Send-GelfInfo'
    'Send-GelfWarning'
    'Send-GelfError'
    'Send-GelfCritical'
    'Send-GelfException'
    'New-GelfLoggingScope'
    'Send-GelfScopedMessage'
    'Measure-GelfDuration'
)
