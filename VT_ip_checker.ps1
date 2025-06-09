# Your VirusTotal API Key
$apiKey = "***********************************************************"

# Get netstat output and extract foreign IPs
$ips = netstat -n | Select-String "TCP" | ForEach-Object {
    ($_ -split "\s+")[3] -replace ":\d+$",""
} | Sort-Object -Unique

# Filter out local/private IPs
$publicIPs = $ips | Where-Object {
    ($_ -notlike "127.*") -and
    ($_ -notlike "192.168.*") -and
    ($_ -notlike "10.*") -and
    ($_ -notlike "172.1[6-9].*") -and
    ($_ -notlike "172.2[0-9].*") -and
    ($_ -notlike "172.3[0-1].*")
}

# Check each public IP using VirusTotal and ipinfo.io
foreach ($ip in $publicIPs) {
    Write-Host "`nChecking IP: $ip" -ForegroundColor Green

    # Lookup with ipinfo.io
    try {
        $info = Invoke-RestMethod -Uri "https://ipinfo.io/$ip/json"
        Write-Host "  Org:     $($info.org)"
        Write-Host "  Country: $($info.country)"
        Write-Host "  Region:  $($info.region)"
    } catch {
        Write-Host "  Error checking IP info: $($_.Exception.Message)" -ForegroundColor Red
    }

    # Lookup with VirusTotal
    try {
        $url = "https://www.virustotal.com/api/v3/ip_addresses/$ip"
        $headers = @{ "x-apikey" = $apiKey }

        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get

        $reputation = $response.data.attributes.reputation
        $lastAnalysis = $response.data.attributes.last_analysis_stats

        # Color-coded reputation
        if ($reputation -lt 0) {
            Write-Host "  Reputation: $reputation" -ForegroundColor Red
        } elseif ($reputation -gt 0) {
            Write-Host "  Reputation: $reputation" -ForegroundColor Green
        } else {
            Write-Host "  Reputation: $reputation" -ForegroundColor Yellow
        }

        # Color-coded malicious
        if ($lastAnalysis.malicious -gt 0) {
            Write-Host "  Malicious:  $($lastAnalysis.malicious)" -ForegroundColor Red
        } else {
            Write-Host "  Malicious:  $($lastAnalysis.malicious)" -ForegroundColor Green
        }

        Write-Host "  Suspicious: $($lastAnalysis.suspicious)"
        Write-Host "  Harmless:   $($lastAnalysis.harmless)"
        Write-Host "  Undetected: $($lastAnalysis.undetected)"

    } catch {
        Write-Host ("  Error checking VirusTotal for {0}: {1}" -f $ip, $_.Exception.Message) -ForegroundColor Red
    }
}

pause
