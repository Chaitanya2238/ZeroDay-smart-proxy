# load_env.ps1 - Load environment variables from .env file

# Read .env file and set environment variables
if (Test-Path ".env") {
    Write-Host "Loading environment variables from .env..." -ForegroundColor Cyan
    
    $envVars = @{}
    Get-Content .env | ForEach-Object {
        $line = $_
        if ($line -match '=') {
            $parts = $line -split '=', 2
            if ($parts.Count -eq 2) {
                $key = $parts[0].Trim()
                $value = $parts[1].Trim()
                $envVars[$key] = $value
                [Environment]::SetEnvironmentVariable($key, $value)
            }
        }
    }
    
    Write-Host "Loaded $($envVars.Count) environment variables:" -ForegroundColor Green
    $envVars.Keys | ForEach-Object {
        $val = $envVars[$_]
        if ($_.ToUpper() -eq 'GOOGLE_API_KEY') {
            # Mask API key for security
            $masked = $val.Substring(0, [Math]::Min(10, $val.Length)) + "***"
            Write-Host "   OK $_ = $masked" -ForegroundColor Green
        } else {
            Write-Host "   OK $_ = $($envVars[$_])" -ForegroundColor Green
        }
    }
    Write-Host ""
} else {
    Write-Host "ERROR: .env file not found!" -ForegroundColor Red
    Write-Host "   Please create .env file with your API key"
    exit 1
}

# Verify API key is set
if ($env:GOOGLE_API_KEY) {
    Write-Host "API KEY is set and ready to use!" -ForegroundColor Green
} else {
    Write-Host "ERROR: GOOGLE_API_KEY not found in .env" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "SUCCESS: You can now run tests without setting environment variables!" -ForegroundColor Cyan
Write-Host ""
