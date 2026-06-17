<#
.SYNOPSIS
    Deploys all KQL detection rules in this repository to a Microsoft Sentinel workspace.

.DESCRIPTION
    Reads rules-manifest.json, loads each .kql file, and creates/updates
    scheduled analytics rules in Microsoft Sentinel.

.PARAMETER ResourceGroup
    Azure Resource Group containing the Log Analytics workspace.

.PARAMETER WorkspaceName
    Name of the Log Analytics / Microsoft Sentinel workspace.

.PARAMETER SubscriptionId
    (Optional) Azure Subscription ID. Uses current context if omitted.

.EXAMPLE
    .\deploy-all-rules.ps1 -ResourceGroup "sentinel-rg" -WorkspaceName "sentinel-ws"
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroup,

    [Parameter(Mandatory = $true)]
    [string]$WorkspaceName,

    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId
)

$ErrorActionPreference = "Stop"

# --- Auth / context ---
if ($SubscriptionId) {
    Write-Host "Setting subscription to $SubscriptionId..."
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
}

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$manifestPath = Join-Path $scriptRoot "rules-manifest.json"

if (-not (Test-Path $manifestPath)) {
    throw "rules-manifest.json not found at $manifestPath"
}

$manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroup -Name $WorkspaceName
$workspaceId = $workspace.CustomerId

Write-Host "Workspace: $WorkspaceName ($workspaceId)" -ForegroundColor Cyan

foreach ($rule in $manifest.rules) {
    $kqlPath = Join-Path $scriptRoot $rule.file
    if (-not (Test-Path $kqlPath)) {
        Write-Warning "Missing KQL file for $($rule.id): $kqlPath"
        continue
    }

    $query = Get-Content $kqlPath -Raw
    Write-Host "Deploying: $($rule.name)" -ForegroundColor Yellow

    $armTemplate = @{
        '$schema'      = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
        contentVersion = "1.0.0.0"
        resources      = @(
            @{
                type       = "Microsoft.OperationalInsights/workspaces/providers/alertRules"
                apiVersion = "2023-12-01-preview"
                name       = "$WorkspaceName/Microsoft.SecurityInsights/$($rule.id)"
                kind       = "Scheduled"
                properties = @{
                    displayName          = $rule.name
                    description          = "Imported from hybrid-AD-evasion-detection repo"
                    severity             = $rule.severity
                    enabled              = $rule.enabled
                    query                = $query
                    queryFrequency       = $rule.queryFrequency
                    queryPeriod          = $rule.queryPeriod
                    triggerOperator      = $rule.triggerOperator
                    triggerThreshold     = $rule.triggerThreshold
                    tactics              = $rule.mitreTactics
                    techniques           = $rule.mitreTechniques
                    suppressionDuration  = "PT1H"
                    suppressionEnabled   = $false
                }
            }
        )
    }

    $tmpFile = [System.IO.Path]::GetTempFileName() + ".json"
    $armTemplate | ConvertTo-Json -Depth 20 | Set-Content $tmpFile

    try {
        New-AzResourceGroupDeployment `
            -ResourceGroupName $ResourceGroup `
            -TemplateFile $tmpFile `
            -Mode Incremental `
            -Verbose | Out-Null
        Write-Host "  ✔ Deployed $($rule.id)" -ForegroundColor Green
    }
    catch {
        Write-Warning "  ✘ Failed $($rule.id): $_"
    }
    finally {
        Remove-Item $tmpFile -ErrorAction SilentlyContinue
    }
}

Write-Host "`nDeployment complete." -ForegroundColor Cyan
