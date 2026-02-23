<#
.SYNOPSIS
    Analyze-BloodHoundData.ps1 - BloodHound ZIP IR Analyzer
.DESCRIPTION
    Parses SharpHound ZIP and produces HTML report + multi-tab XLSX.
    Requires BH_IR_Template.html in the same directory.
.PARAMETER ZipPath
    Path to the BloodHound ZIP file.
.PARAMETER OutputPath
    Path for the HTML report.
.PARAMETER XlsxPath
    Path for the Excel workbook.
.EXAMPLE
    .\Analyze-BloodHoundData.ps1 -ZipPath .\bloodhound.zip
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateScript({Test-Path $_ -PathType Leaf})][string]$ZipPath,
    [Parameter(Mandatory=$false)][string]$OutputPath = (Join-Path $PWD "BloodHound_IR_Report.html"),
    [Parameter(Mandatory=$false)][string]$XlsxPath  = (Join-Path $PWD "BloodHound_IR_Report.xlsx")
)
$ErrorActionPreference = 'Stop'
$script:ReportTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

function Extract-BloodHoundData {
    param([string]$Path)
    $data = @{ Users=@(); Computers=@(); Groups=@(); Domains=@(); GPOs=@(); OUs=@(); Containers=@() }
    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("BH_IR_" + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $tempDir -Force
    try {
        Write-Host "[*] Extracting ZIP..." -ForegroundColor Cyan
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($Path, $tempDir)
        foreach ($file in (Get-ChildItem -Path $tempDir -Filter "*.json" -Recurse)) {
            Write-Host ("    Parsing: " + $file.Name) -ForegroundColor DarkGray
            try {
                $json = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
                $fileType = $null; $items = @()
                if ($json.meta -and $json.meta.type) { $fileType = $json.meta.type.ToLower(); $items = @($json.data) }
                elseif ($json.data -and $json.data.Count -gt 0) {
                    $fn = $file.Name.ToLower()
                    if($fn -match 'user'){$fileType='users'}elseif($fn -match 'comp'){$fileType='computers'}
                    elseif($fn -match 'group'){$fileType='groups'}elseif($fn -match 'domain'){$fileType='domains'}
                    elseif($fn -match 'gpo'){$fileType='gpos'}elseif($fn -match 'ou'){$fileType='ous'}
                    elseif($fn -match 'container'){$fileType='containers'}
                    $items = @($json.data)
                } elseif ($json -is [System.Collections.IEnumerable] -and $json.Count -gt 0) {
                    $fn = $file.Name.ToLower()
                    if($fn -match 'user'){$fileType='users'}elseif($fn -match 'comp'){$fileType='computers'}
                    elseif($fn -match 'group'){$fileType='groups'}elseif($fn -match 'domain'){$fileType='domains'}
                    elseif($fn -match 'gpo'){$fileType='gpos'}elseif($fn -match 'ou'){$fileType='ous'}
                    $items = @($json)
                }
                switch ($fileType) {
                    'users'{$data.Users+=$items}'computers'{$data.Computers+=$items}'groups'{$data.Groups+=$items}
                    'domains'{$data.Domains+=$items}'gpos'{$data.GPOs+=$items}'ous'{$data.OUs+=$items}'containers'{$data.Containers+=$items}
                }
            } catch { Write-Warning ("    Could not parse " + $file.Name + ": " + $_) }
        }
    } finally { Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host ("[*] Parsed: " + $data.Users.Count + " users, " + $data.Computers.Count + " computers, " + $data.Groups.Count + " groups") -ForegroundColor Green
    return $data
}

function Get-Prop { param($Object,[string]$Path,$Default=$null); $c=$Object; foreach($p in $Path.Split('.')){if($null -eq $c){return $Default};$c=$c.$p}; if($null -eq $c){return $Default}; return $c }
function Convert-EpochToDate { param($Epoch); if($null -eq $Epoch -or $Epoch -eq 0 -or $Epoch -eq -1){return $null}; try{if($Epoch -gt 1e12){$Epoch=$Epoch/1000};return [DateTimeOffset]::FromUnixTimeSeconds([long]$Epoch).DateTime.ToUniversalTime()}catch{return $null} }
function Format-DateSafe { param($DateObj); if($null -eq $DateObj){return "N/A"}; try{return $DateObj.ToString("yyyy-MM-dd HH:mm:ss")+" UTC"}catch{return "N/A"} }

function Analyze-DomainAndEnterpriseAdmins {
    param($Data)
    Write-Host "[*] Identifying DA/EA members..." -ForegroundColor Cyan
    $ul = @{}; foreach ($u in $Data.Users) { $sid=Get-Prop $u 'ObjectIdentifier' ''; if($sid){$ul[$sid]=$u} }
    $results = @()
    foreach ($group in $Data.Groups) {
        $gn = (Get-Prop $group 'Properties.name' '').ToUpper()
        if ($gn -notlike '*DOMAIN ADMINS*' -and $gn -notlike '*ENTERPRISE ADMINS*') { continue }
        foreach ($member in @(Get-Prop $group 'Members' @())) {
            $sid = Get-Prop $member 'ObjectIdentifier' (Get-Prop $member 'MemberId' '')
            $mt = Get-Prop $member 'ObjectType' (Get-Prop $member 'MemberType' 'Unknown')
            if ($mt -ne 'User' -and -not $ul.ContainsKey($sid)) { continue }
            $u = $ul[$sid]
            $results += [PSCustomObject]@{
                Group=Get-Prop $group 'Properties.name' ''; UserName=Get-Prop $u 'Properties.name' $sid; SamAccountName=Get-Prop $u 'Properties.samaccountname' ''; SID=$sid
                Enabled=Get-Prop $u 'Properties.enabled' $null; LastLogon=Format-DateSafe(Convert-EpochToDate(Get-Prop $u 'Properties.lastlogon' $null))
                PasswordLastSet=Format-DateSafe(Convert-EpochToDate(Get-Prop $u 'Properties.pwdlastset' $null)); WhenCreated=Format-DateSafe(Convert-EpochToDate(Get-Prop $u 'Properties.whencreated' $null))
                AdminCount=Get-Prop $u 'Properties.admincount' $false; Sensitive=Get-Prop $u 'Properties.sensitive' $false; Description=Get-Prop $u 'Properties.description' ''
                HasSPN=Get-Prop $u 'Properties.hasspn' $false; DontReqPreauth=Get-Prop $u 'Properties.dontreqpreauth' $false; UnconstrainedDeleg=Get-Prop $u 'Properties.unconstraineddelegation' $false
            }
        }
    }
    return $results
}

function Analyze-RecentlyCreatedUsers {
    param($Data,[int]$DaysBack=90)
    Write-Host "[*] Finding recently created users..." -ForegroundColor Cyan
    $cutoff=(Get-Date).AddDays(-$DaysBack).ToUniversalTime(); $results=@()
    foreach ($u in $Data.Users) {
        $wc=Convert-EpochToDate(Get-Prop $u 'Properties.whencreated' $null); if($null -eq $wc -or $wc -lt $cutoff){continue}
        $results += [PSCustomObject]@{
            UserName=Get-Prop $u 'Properties.name' ''; SamAccountName=Get-Prop $u 'Properties.samaccountname' ''; SID=Get-Prop $u 'ObjectIdentifier' ''
            Enabled=Get-Prop $u 'Properties.enabled' $null; WhenCreated=Format-DateSafe $wc; LastLogon=Format-DateSafe(Convert-EpochToDate(Get-Prop $u 'Properties.lastlogon' $null))
            PasswordLastSet=Format-DateSafe(Convert-EpochToDate(Get-Prop $u 'Properties.pwdlastset' $null)); AdminCount=Get-Prop $u 'Properties.admincount' $false
            HasSPN=Get-Prop $u 'Properties.hasspn' $false; DontReqPreauth=Get-Prop $u 'Properties.dontreqpreauth' $false; Description=Get-Prop $u 'Properties.description' ''
        }
    }
    return $results
}

function Analyze-KerberoastableUsers {
    param($Data)
    Write-Host "[*] Finding Kerberoastable users..." -ForegroundColor Cyan
    $results=@()
    foreach ($u in $Data.Users) {
        if(-not(Get-Prop $u 'Properties.hasspn' $false) -or -not(Get-Prop $u 'Properties.enabled' $false)){continue}
        $results += [PSCustomObject]@{
            UserName=Get-Prop $u 'Properties.name' ''; SamAccountName=Get-Prop $u 'Properties.samaccountname' ''; SID=Get-Prop $u 'ObjectIdentifier' ''
            AdminCount=Get-Prop $u 'Properties.admincount' $false; PasswordLastSet=Format-DateSafe(Convert-EpochToDate(Get-Prop $u 'Properties.pwdlastset' $null))
            LastLogon=Format-DateSafe(Convert-EpochToDate(Get-Prop $u 'Properties.lastlogon' $null)); SPNs=(@(Get-Prop $u 'Properties.serviceprincipalnames' @()) -join '; '); Description=Get-Prop $u 'Properties.description' ''
        }
    }
    return $results
}

function Analyze-ASREPRoastable {
    param($Data)
    Write-Host "[*] Finding AS-REP Roastable users..." -ForegroundColor Cyan
    $results=@()
    foreach ($u in $Data.Users) {
        if(-not(Get-Prop $u 'Properties.dontreqpreauth' $false) -or -not(Get-Prop $u 'Properties.enabled' $false)){continue}
        $results += [PSCustomObject]@{
            UserName=Get-Prop $u 'Properties.name' ''; SamAccountName=Get-Prop $u 'Properties.samaccountname' ''; SID=Get-Prop $u 'ObjectIdentifier' ''
            AdminCount=Get-Prop $u 'Properties.admincount' $false; PasswordLastSet=Format-DateSafe(Convert-EpochToDate(Get-Prop $u 'Properties.pwdlastset' $null)); Description=Get-Prop $u 'Properties.description' ''
        }
    }
    return $results
}

function Analyze-UnconstrainedDelegation {
    param($Data)
    Write-Host "[*] Finding unconstrained delegation..." -ForegroundColor Cyan
    $results=@()
    foreach ($c in $Data.Computers) {
        if(-not(Get-Prop $c 'Properties.unconstraineddelegation' $false)){continue}
        $results += [PSCustomObject]@{
            ComputerName=Get-Prop $c 'Properties.name' ''; SID=Get-Prop $c 'ObjectIdentifier' ''; Enabled=Get-Prop $c 'Properties.enabled' $true
            IsDC=Get-Prop $c 'Properties.isdc' $false; OS=Get-Prop $c 'Properties.operatingsystem' ''; LastLogon=Format-DateSafe(Convert-EpochToDate(Get-Prop $c 'Properties.lastlogon' $null)); Description=Get-Prop $c 'Properties.description' ''
        }
    }
    return $results
}

function Analyze-ConstrainedDelegation {
    param($Data)
    Write-Host "[*] Finding constrained delegation..." -ForegroundColor Cyan
    $results=@()
    foreach ($c in $Data.Computers) {
        $allowed = @(Get-Prop $c 'Properties.allowedtodelegate' @()); if($allowed.Count -eq 0){continue}
        $results += [PSCustomObject]@{ Name=Get-Prop $c 'Properties.name' ''; SID=Get-Prop $c 'ObjectIdentifier' ''; Type='Computer'; Enabled=Get-Prop $c 'Properties.enabled' $true; OS=Get-Prop $c 'Properties.operatingsystem' ''; AllowedToDelegate=($allowed -join '; ') }
    }
    foreach ($u in $Data.Users) {
        $allowed = @(Get-Prop $u 'Properties.allowedtodelegate' @()); if($allowed.Count -eq 0){continue}
        $results += [PSCustomObject]@{ Name=Get-Prop $u 'Properties.name' ''; SID=Get-Prop $u 'ObjectIdentifier' ''; Type='User'; Enabled=Get-Prop $u 'Properties.enabled' $false; OS='N/A'; AllowedToDelegate=($allowed -join '; ') }
    }
    return $results
}

function Analyze-StalePasswords {
    param($Data,[int]$DaysStale=365)
    Write-Host "[*] Finding stale passwords..." -ForegroundColor Cyan
    $cutoff=(Get-Date).AddDays(-$DaysStale).ToUniversalTime(); $results=@()
    foreach ($u in $Data.Users) {
        if(-not(Get-Prop $u 'Properties.enabled' $false)){continue}
        $pls=Convert-EpochToDate(Get-Prop $u 'Properties.pwdlastset' $null); if($null -eq $pls -or $pls -gt $cutoff){continue}
        $results += [PSCustomObject]@{
            UserName=Get-Prop $u 'Properties.name' ''; SamAccountName=Get-Prop $u 'Properties.samaccountname' ''
            PasswordLastSet=Format-DateSafe $pls; PwdNeverExpires=Get-Prop $u 'Properties.pwdneverexpires' $false
            AdminCount=Get-Prop $u 'Properties.admincount' $false; LastLogon=Format-DateSafe(Convert-EpochToDate(Get-Prop $u 'Properties.lastlogon' $null))
            DaysSincePwdSet=[math]::Round(((Get-Date).ToUniversalTime()-$pls).TotalDays)
        }
    }
    return ($results | Sort-Object DaysSincePwdSet -Descending)
}

function Analyze-NeverExpirePasswords {
    param($Data)
    Write-Host "[*] Finding password-never-expires..." -ForegroundColor Cyan
    $results=@()
    foreach ($u in $Data.Users) {
        if(-not(Get-Prop $u 'Properties.enabled' $false) -or -not(Get-Prop $u 'Properties.pwdneverexpires' $false)){continue}
        $results += [PSCustomObject]@{
            UserName=Get-Prop $u 'Properties.name' ''; SamAccountName=Get-Prop $u 'Properties.samaccountname' ''
            AdminCount=Get-Prop $u 'Properties.admincount' $false; PasswordLastSet=Format-DateSafe(Convert-EpochToDate(Get-Prop $u 'Properties.pwdlastset' $null))
            LastLogon=Format-DateSafe(Convert-EpochToDate(Get-Prop $u 'Properties.lastlogon' $null)); HasSPN=Get-Prop $u 'Properties.hasspn' $false; Description=Get-Prop $u 'Properties.description' ''
        }
    }
    return $results
}

function Analyze-InactiveAccounts {
    param($Data,[int]$DaysInactive=90)
    Write-Host "[*] Finding inactive accounts..." -ForegroundColor Cyan
    $cutoff=(Get-Date).AddDays(-$DaysInactive).ToUniversalTime(); $results=@()
    foreach ($u in $Data.Users) {
        if(-not(Get-Prop $u 'Properties.enabled' $false)){continue}
        $ll=Convert-EpochToDate(Get-Prop $u 'Properties.lastlogon' $null)
        $llt=Convert-EpochToDate(Get-Prop $u 'Properties.lastlogontimestamp' $null)
        $latest=$ll; if($null -ne $llt -and ($null -eq $latest -or $llt -gt $latest)){$latest=$llt}
        if($null -eq $latest -or $latest -gt $cutoff){continue}
        $results += [PSCustomObject]@{
            UserName=Get-Prop $u 'Properties.name' ''; SamAccountName=Get-Prop $u 'Properties.samaccountname' ''; SID=Get-Prop $u 'ObjectIdentifier' ''
            LastLogon=Format-DateSafe $latest; DaysSinceLogon=[math]::Round(((Get-Date).ToUniversalTime()-$latest).TotalDays)
            AdminCount=Get-Prop $u 'Properties.admincount' $false; HasSPN=Get-Prop $u 'Properties.hasspn' $false; Description=Get-Prop $u 'Properties.description' ''
        }
    }
    return ($results | Sort-Object DaysSinceLogon -Descending)
}

function Analyze-NotInProtectedUsers {
    param($Data)
    Write-Host "[*] Finding admins not in Protected Users..." -ForegroundColor Cyan
    $protectedSIDs = @{}
    foreach ($g in $Data.Groups) {
        if ((Get-Prop $g 'Properties.name' '').ToUpper() -like '*PROTECTED USERS*') {
            foreach ($m in @(Get-Prop $g 'Members' @())) { $sid=Get-Prop $m 'ObjectIdentifier' (Get-Prop $m 'MemberId' ''); if($sid){$protectedSIDs[$sid]=$true} }
        }
    }
    $results=@()
    foreach ($u in $Data.Users) {
        if(-not(Get-Prop $u 'Properties.admincount' $false) -or -not(Get-Prop $u 'Properties.enabled' $false)){continue}
        $sid=Get-Prop $u 'ObjectIdentifier' ''; if($protectedSIDs.ContainsKey($sid)){continue}
        $results += [PSCustomObject]@{
            UserName=Get-Prop $u 'Properties.name' ''; SamAccountName=Get-Prop $u 'Properties.samaccountname' ''; SID=$sid
            HasSPN=Get-Prop $u 'Properties.hasspn' $false; DontReqPreauth=Get-Prop $u 'Properties.dontreqpreauth' $false; Description=Get-Prop $u 'Properties.description' ''
        }
    }
    return $results
}

function Analyze-LAPSStatus {
    param($Data)
    Write-Host "[*] Checking LAPS deployment..." -ForegroundColor Cyan
    $results=@()
    foreach ($c in $Data.Computers) {
        if(Get-Prop $c 'Properties.isdc' $false){continue}
        if(-not(Get-Prop $c 'Properties.enabled' $true)){continue}
        if((Get-Prop $c 'Properties.haslaps' $null) -eq $true){continue}
        $results += [PSCustomObject]@{ ComputerName=Get-Prop $c 'Properties.name' ''; OS=Get-Prop $c 'Properties.operatingsystem' ''; HasLAPS=$false; LastLogon=Format-DateSafe(Convert-EpochToDate(Get-Prop $c 'Properties.lastlogon' $null)) }
    }
    return $results
}

function Analyze-DomainTrusts {
    param($Data)
    Write-Host "[*] Analyzing domain trusts..." -ForegroundColor Cyan
    $results=@()
    foreach ($domain in $Data.Domains) {
        foreach ($trust in @(Get-Prop $domain 'Trusts' @())) {
            $td = switch(Get-Prop $trust 'TrustDirection' -1){0{'Disabled'};1{'Inbound'};2{'Outbound'};3{'Bidirectional'};default{'Unknown'}}
            $tt = switch(Get-Prop $trust 'TrustType' -1){1{'WINDOWS_NON_AD'};2{'WINDOWS_AD'};3{'MIT'};default{'Unknown'}}
            $results += [PSCustomObject]@{ SourceDomain=Get-Prop $domain 'Properties.name' ''; TargetDomain=Get-Prop $trust 'TargetDomainName' 'Unknown'; TrustDirection=$td; TrustType=$tt; IsTransitive=Get-Prop $trust 'IsTransitive' $false; SIDFiltering=Get-Prop $trust 'SidFilteringEnabled' $true }
        }
    }
    return $results
}

function Analyze-UserStatistics {
    param($Data)
    Write-Host "[*] Computing statistics..." -ForegroundColor Cyan
    return [PSCustomObject]@{
        TotalUsers=$Data.Users.Count; EnabledUsers=@($Data.Users|Where-Object{(Get-Prop $_ 'Properties.enabled' $false)-eq $true}).Count
        DisabledUsers=$Data.Users.Count-@($Data.Users|Where-Object{(Get-Prop $_ 'Properties.enabled' $false)-eq $true}).Count
        UsersWithSPN=@($Data.Users|Where-Object{(Get-Prop $_ 'Properties.hasspn' $false)-eq $true}).Count
        NoPreauth=@($Data.Users|Where-Object{(Get-Prop $_ 'Properties.dontreqpreauth' $false)-eq $true}).Count
        AdminCountSet=@($Data.Users|Where-Object{(Get-Prop $_ 'Properties.admincount' $false)-eq $true}).Count
        PwdNeverExpires=@($Data.Users|Where-Object{(Get-Prop $_ 'Properties.pwdneverexpires' $false)-eq $true}).Count
        TotalComputers=$Data.Computers.Count; TotalGroups=$Data.Groups.Count; TotalDomains=$Data.Domains.Count
    }
}

function Analyze-HighValueTargets {
    param($Data)
    Write-Host "[*] Identifying high-value targets..." -ForegroundColor Cyan
    $results=@()
    foreach ($u in $Data.Users) {
        if(-not(Get-Prop $u 'Properties.enabled' $false)){continue}
        $hv=Get-Prop $u 'Properties.highvalue' $false; $ac=Get-Prop $u 'Properties.admincount' $false
        $spn=Get-Prop $u 'Properties.hasspn' $false; $dr=Get-Prop $u 'Properties.dontreqpreauth' $false
        $ud=Get-Prop $u 'Properties.unconstraineddelegation' $false; $sn=Get-Prop $u 'Properties.sensitive' $false
        if(-not $hv -and -not($ac -and ($spn -or $dr -or $ud))){continue}
        $rf=@(); if($hv){$rf+='HighValue'}; if($ac){$rf+='AdminCount'}; if($spn){$rf+='Kerberoastable'}; if($dr){$rf+='ASREPRoastable'}; if($ud){$rf+='UnconstrainedDeleg'}; if($sn){$rf+='Sensitive'}
        $results += [PSCustomObject]@{
            UserName=Get-Prop $u 'Properties.name' ''; SamAccountName=Get-Prop $u 'Properties.samaccountname' ''; SID=Get-Prop $u 'ObjectIdentifier' ''
            RiskFactors=($rf -join ', '); PasswordLastSet=Format-DateSafe(Convert-EpochToDate(Get-Prop $u 'Properties.pwdlastset' $null))
            LastLogon=Format-DateSafe(Convert-EpochToDate(Get-Prop $u 'Properties.lastlogon' $null)); Description=Get-Prop $u 'Properties.description' ''
        }
    }
    return $results
}

function Analyze-ComputerOS {
    param($Data)
    Write-Host "[*] Analyzing operating systems..." -ForegroundColor Cyan
    $oc=@{}; foreach($c in $Data.Computers){$os=Get-Prop $c 'Properties.operatingsystem' 'Unknown'; if(-not $os){$os='Unknown'}; if(-not $oc.ContainsKey($os)){$oc[$os]=0}; $oc[$os]++}
    $results=@()
    foreach($kv in ($oc.GetEnumerator()|Sort-Object Value -Descending)){
        $leg=$false; if($kv.Key -match '2003|2008|XP|Vista|Windows 7|Windows 8 '){$leg=$true}
        $results+=[PSCustomObject]@{OperatingSystem=$kv.Key;Count=$kv.Value;LegacyOS=$leg}
    }
    return $results
}

function Analyze-DomainControllers {
    param($Data)
    Write-Host "[*] Identifying Domain Controllers..." -ForegroundColor Cyan
    $results=@()
    foreach($c in $Data.Computers){
        if(-not(Get-Prop $c 'Properties.isdc' $false)){continue}
        $results+=[PSCustomObject]@{ComputerName=Get-Prop $c 'Properties.name' '';OS=Get-Prop $c 'Properties.operatingsystem' '';Enabled=Get-Prop $c 'Properties.enabled' $true;LastLogon=Format-DateSafe(Convert-EpochToDate(Get-Prop $c 'Properties.lastlogon' $null));UnconDeleg=Get-Prop $c 'Properties.unconstraineddelegation' $false;SID=Get-Prop $c 'ObjectIdentifier' ''}
    }
    return $results
}

function Analyze-DomainPasswordPolicy {
    param($Data)
    Write-Host "[*] Extracting domain password policy..." -ForegroundColor Cyan
    $results=@()
    foreach ($d in $Data.Domains) {
        $minPwd=Get-Prop $d 'Properties.minpwdlength' $null; $pwdHist=Get-Prop $d 'Properties.pwdhistorylength' $null
        $lockout=Get-Prop $d 'Properties.lockoutthreshold' $null; $pwdProps=Get-Prop $d 'Properties.pwdproperties' $null
        $maq=Get-Prop $d 'Properties.machineaccountquota' $null; $funcLvl=Get-Prop $d 'Properties.functionallevel' 'Unknown'
        $complexity='Unknown'; $reversible='Unknown'
        if ($null -ne $pwdProps) { $complexity=if($pwdProps -band 1){'Enabled'}else{'DISABLED'}; $reversible=if($pwdProps -band 16){'ENABLED (DANGEROUS)'}else{'Disabled'} }
        $findings=@()
        if($null -ne $minPwd -and $minPwd -lt 14){$findings+='Min pwd length '+$minPwd+' (recommend 14+)'}
        if($null -ne $minPwd -and $minPwd -ge 14){$findings+='Min pwd length '+$minPwd+' (GOOD)'}
        if($complexity -eq 'DISABLED'){$findings+='Complexity DISABLED'}
        if($reversible -like '*DANGEROUS*'){$findings+='Reversible encryption ENABLED'}
        if($null -ne $lockout -and $lockout -eq 0){$findings+='No account lockout (threshold=0)'}
        if($null -ne $pwdHist -and $pwdHist -lt 12){$findings+='Pwd history '+$pwdHist+' (recommend 12+)'}
        if($null -ne $maq -and $maq -gt 0){$findings+='MachineAccountQuota='+$maq+' (users can join computers!)'}
        if($null -ne $maq -and $maq -eq 0){$findings+='MachineAccountQuota=0 (GOOD)'}
        if($funcLvl -match '2008|2003|2000'){$findings+='Functional level '+$funcLvl+' (outdated)'}
        $results += [PSCustomObject]@{
            DomainName=Get-Prop $d 'Properties.name' ''; FunctionalLevel=$funcLvl
            MinPasswordLength=if($null -ne $minPwd){$minPwd}else{'N/A'}; PasswordComplexity=$complexity
            PasswordHistoryLength=if($null -ne $pwdHist){$pwdHist}else{'N/A'}; LockoutThreshold=if($null -ne $lockout){$lockout}else{'N/A'}
            ReversibleEncryption=$reversible; MachineAccountQuota=if($null -ne $maq){$maq}else{'N/A'}
            Findings=($findings -join ' | ')
        }
    }
    return $results
}

function Analyze-PasswordNotRequired {
    param($Data)
    Write-Host "[*] Finding accounts with PASSWD_NOTREQD flag..." -ForegroundColor Cyan
    $results=@()
    foreach ($u in $Data.Users) {
        if(-not(Get-Prop $u 'Properties.passwordnotreqd' $false)){continue}
        $results += [PSCustomObject]@{
            UserName=Get-Prop $u 'Properties.name' ''; SamAccountName=Get-Prop $u 'Properties.samaccountname' ''; SID=Get-Prop $u 'ObjectIdentifier' ''
            Enabled=Get-Prop $u 'Properties.enabled' $false; PasswordNotRequired=$true
            AdminCount=Get-Prop $u 'Properties.admincount' $false; HasSPN=Get-Prop $u 'Properties.hasspn' $false
            PasswordLastSet=Format-DateSafe(Convert-EpochToDate(Get-Prop $u 'Properties.pwdlastset' $null))
            LastLogon=Format-DateSafe(Convert-EpochToDate(Get-Prop $u 'Properties.lastlogon' $null)); Description=Get-Prop $u 'Properties.description' ''
        }
    }
    return $results
}


function Make-TableHtml {
    param([array]$Data,[string[]]$Columns)
    if(-not $Data -or $Data.Count -eq 0){return '<p class="empty-state">No results found.</p>'}
    $sb=[System.Text.StringBuilder]::new()
    $id = 'tbl_' + [guid]::NewGuid().ToString('N').Substring(0,8)
    [void]$sb.Append('<div class="table-wrap" id="'+$id+'"><table><thead><tr>')
    foreach($col in $Columns){[void]$sb.Append('<th>'+[System.Web.HttpUtility]::HtmlEncode($col)+'</th>')}
    [void]$sb.Append('</tr></thead><tbody>')
    $rowIdx=0
    foreach($row in $Data){
        $hideClass=''; if($rowIdx -ge 10){$hideClass=' class="hidden-row" style="display:none"'}
        [void]$sb.Append('<tr'+$hideClass+'>')
        foreach($col in $Columns){
            $val=$row.$col; if($null -eq $val){$val=''}; $cls=''
            if($val -eq $true){$val='YES';$cls=' class="val-true"'}
            if($val -eq $false){$val='NO';$cls=' class="val-false"'}
            [void]$sb.Append('<td'+$cls+'>'+[System.Web.HttpUtility]::HtmlEncode($val.ToString())+'</td>')
        }
        [void]$sb.Append('</tr>'); $rowIdx++
    }
    [void]$sb.Append('</tbody></table>')
    if($Data.Count -gt 10){
        $rem=$Data.Count-10
        $btnText = 'Show all ' + $Data.Count + ' rows (' + $rem + ' more)'
        [void]$sb.Append('<button class="expand-btn" onclick="toggleRows(''' + $id + ''',this)">' + $btnText + '</button>')
    }
    [void]$sb.Append('</div>')
    return $sb.ToString()
}

function Build-HtmlReport {
    param($AllData,[string]$ZipFileName)
    $enabledAdmins = @($AllData.DAEAMembers | Where-Object { $_.Enabled -eq $true })
    $tbl=@{}
    $tbl['ENABLEDDA']=Make-TableHtml -Data $enabledAdmins -Columns @('Group','UserName','SamAccountName','SID','Enabled','WhenCreated','LastLogon','PasswordLastSet','AdminCount','HasSPN','DontReqPreauth','UnconstrainedDeleg','Sensitive','Description')
    $tbl['ALLDA']=Make-TableHtml -Data $AllData.DAEAMembers -Columns @('Group','UserName','SamAccountName','SID','Enabled','WhenCreated','LastLogon','PasswordLastSet','AdminCount','HasSPN','DontReqPreauth','Description')
    $tbl['NEWUSERS']=Make-TableHtml -Data $AllData.RecentUsers -Columns @('UserName','SamAccountName','SID','Enabled','WhenCreated','LastLogon','PasswordLastSet','AdminCount','HasSPN','DontReqPreauth','Description')
    $tbl['KERB']=Make-TableHtml -Data $AllData.Kerberoastable -Columns @('UserName','SamAccountName','SID','AdminCount','PasswordLastSet','LastLogon','SPNs','Description')
    $tbl['ASREP']=Make-TableHtml -Data $AllData.ASREPRoastable -Columns @('UserName','SamAccountName','SID','AdminCount','PasswordLastSet','Description')
    $tbl['UNCONSTRAINED']=Make-TableHtml -Data $AllData.UnconstrainedDeleg -Columns @('ComputerName','SID','Enabled','IsDC','OS','LastLogon','Description')
    $tbl['CONSTRAINED']=Make-TableHtml -Data $AllData.ConstrainedDeleg -Columns @('Name','SID','Type','Enabled','OS','AllowedToDelegate')
    $tbl['HVT']=Make-TableHtml -Data $AllData.HighValueTargets -Columns @('UserName','SamAccountName','SID','RiskFactors','PasswordLastSet','LastLogon','Description')
    $tbl['STALE']=Make-TableHtml -Data $AllData.StalePasswords -Columns @('UserName','SamAccountName','PasswordLastSet','DaysSincePwdSet','PwdNeverExpires','AdminCount','LastLogon')
    $tbl['NEVEREXP']=Make-TableHtml -Data $AllData.NeverExpire -Columns @('UserName','SamAccountName','AdminCount','PasswordLastSet','LastLogon','HasSPN','Description')
    $tbl['INACTIVE']=Make-TableHtml -Data $AllData.InactiveAccounts -Columns @('UserName','SamAccountName','SID','LastLogon','DaysSinceLogon','AdminCount','HasSPN','Description')
    $tbl['NOTPROTECTED']=Make-TableHtml -Data $AllData.NotInProtectedUsers -Columns @('UserName','SamAccountName','SID','HasSPN','DontReqPreauth','Description')
    $tbl['LAPS']=Make-TableHtml -Data $AllData.LAPSMissing -Columns @('ComputerName','OS','HasLAPS','LastLogon')
    $tbl['DCS']=Make-TableHtml -Data $AllData.DomainControllers -Columns @('ComputerName','OS','Enabled','LastLogon','UnconDeleg','SID')
    $tbl['OS']=Make-TableHtml -Data $AllData.OSBreakdown -Columns @('OperatingSystem','Count','LegacyOS')
    $tbl['TRUSTS']=Make-TableHtml -Data $AllData.Trusts -Columns @('SourceDomain','TargetDomain','TrustDirection','TrustType','IsTransitive','SIDFiltering')
    $tbl['PWDPOLICY']=Make-TableHtml -Data $AllData.PasswordPolicy -Columns @('DomainName','FunctionalLevel','MinPasswordLength','PasswordComplexity','PasswordHistoryLength','LockoutThreshold','ReversibleEncryption','MachineAccountQuota','Findings')
    $tbl['PWDNOTREQD']=Make-TableHtml -Data $AllData.PasswordNotRequired -Columns @('UserName','SamAccountName','SID','Enabled','PasswordNotRequired','AdminCount','HasSPN','PasswordLastSet','LastLogon','Description')

    $scriptDir = Split-Path -Parent $MyInvocation.ScriptName
    $templatePath = Join-Path $scriptDir "BH_IR_Template.html"
    if (-not (Test-Path $templatePath)) { Write-Error ("Template not found: " + $templatePath); return }
    $template = [System.IO.File]::ReadAllText($templatePath)
    $S=$AllData.Stats
    $template=$template.Replace('{{TIMESTAMP}}',$script:ReportTimestamp).Replace('{{ZIPNAME}}',[System.Web.HttpUtility]::HtmlEncode($ZipFileName))
    $template=$template.Replace('{{TOTAL_USERS}}',[string]$S.TotalUsers).Replace('{{ENABLED_USERS}}',[string]$S.EnabledUsers).Replace('{{DISABLED_USERS}}',[string]$S.DisabledUsers)
    $template=$template.Replace('{{ADMIN_COUNT}}',[string]$S.AdminCountSet).Replace('{{KERBEROASTABLE_CNT}}',[string]$S.UsersWithSPN).Replace('{{ASREP_CNT}}',[string]$S.NoPreauth)
    $template=$template.Replace('{{PWD_NEVER_EXP}}',[string]$S.PwdNeverExpires).Replace('{{TOTAL_COMPUTERS}}',[string]$S.TotalComputers).Replace('{{TOTAL_GROUPS}}',[string]$S.TotalGroups).Replace('{{TOTAL_DOMAINS}}',[string]$S.TotalDomains)
    $template=$template.Replace('{{CNT_ENA_DA}}',[string]$enabledAdmins.Count).Replace('{{CNT_ALL_DA}}',[string]$AllData.DAEAMembers.Count)
    $template=$template.Replace('{{CNT_NEW_USERS}}',[string]$AllData.RecentUsers.Count).Replace('{{CNT_KERB}}',[string]$AllData.Kerberoastable.Count)
    $template=$template.Replace('{{CNT_ASREP}}',[string]$AllData.ASREPRoastable.Count).Replace('{{CNT_UNCON}}',[string]$AllData.UnconstrainedDeleg.Count)
    $template=$template.Replace('{{CNT_CONSTRAINED}}',[string]$AllData.ConstrainedDeleg.Count).Replace('{{CNT_HVT}}',[string]$AllData.HighValueTargets.Count)
    $template=$template.Replace('{{CNT_STALE}}',[string]$AllData.StalePasswords.Count).Replace('{{CNT_NEVER_EXP}}',[string]$AllData.NeverExpire.Count)
    $template=$template.Replace('{{CNT_INACTIVE}}',[string]$AllData.InactiveAccounts.Count).Replace('{{CNT_NOT_PROTECTED}}',[string]$AllData.NotInProtectedUsers.Count)
    $template=$template.Replace('{{CNT_LAPS}}',[string]$AllData.LAPSMissing.Count).Replace('{{CNT_DCS}}',[string]$AllData.DomainControllers.Count)
    $template=$template.Replace('{{CNT_OS}}',[string]$AllData.OSBreakdown.Count).Replace('{{CNT_TRUSTS}}',[string]$AllData.Trusts.Count)
    $template=$template.Replace('{{CNT_PWDNOTREQD}}',[string]$AllData.PasswordNotRequired.Count)
    foreach($key in $tbl.Keys){$template=$template.Replace('{{TBL_'+$key+'}}',$tbl[$key])}
    return $template
}

function Export-ToXlsx {
    param($AllData,[string]$Path)
    Write-Host "[*] Exporting to XLSX..." -ForegroundColor Cyan
    $hasModule=$false
    try{Import-Module ImportExcel -ErrorAction Stop;$hasModule=$true}catch{}
    if(-not $hasModule){try{Install-Module ImportExcel -Scope CurrentUser -Force -ErrorAction Stop;Import-Module ImportExcel -ErrorAction Stop;$hasModule=$true}catch{Write-Warning "ImportExcel not available. Falling back to CSV."}}
    $enabledAdmins=@($AllData.DAEAMembers|Where-Object{$_.Enabled -eq $true})
    $sheets=[ordered]@{
        'Enabled DA-EA'=$enabledAdmins;'All DA-EA'=$AllData.DAEAMembers;'New Users (90d)'=$AllData.RecentUsers
        'Kerberoastable'=$AllData.Kerberoastable;'ASREP Roastable'=$AllData.ASREPRoastable
        'Unconstrained Deleg'=$AllData.UnconstrainedDeleg;'Constrained Deleg'=$AllData.ConstrainedDeleg
        'High-Value Targets'=$AllData.HighValueTargets;'Stale Passwords'=$AllData.StalePasswords
        'PwdNeverExpires'=$AllData.NeverExpire;'Inactive Accounts'=$AllData.InactiveAccounts
        'Not ProtectedUsers'=$AllData.NotInProtectedUsers;'LAPS Missing'=$AllData.LAPSMissing
        'Domain Controllers'=$AllData.DomainControllers;'OS Breakdown'=$AllData.OSBreakdown
        'Domain Trusts'=$AllData.Trusts;'Password Policy'=$AllData.PasswordPolicy
        'Pwd Not Required'=$AllData.PasswordNotRequired
    }
    if($hasModule){
        if(Test-Path $Path){Remove-Item $Path -Force}
        foreach($sn in $sheets.Keys){$d=$sheets[$sn]; if($null -eq $d -or @($d).Count -eq 0){$d=@([PSCustomObject]@{Note='No data found'})}; $d|Export-Excel -Path $Path -WorksheetName $sn -AutoSize -FreezeTopRow -BoldTopRow -Append}
        Write-Host ("[+] XLSX saved to: "+$Path) -ForegroundColor Green
    }else{
        $csvDir=[System.IO.Path]::ChangeExtension($Path,$null)+"_CSVs"; $null=New-Item -ItemType Directory -Path $csvDir -Force
        foreach($sn in $sheets.Keys){$d=$sheets[$sn]; if($null -ne $d -and @($d).Count -gt 0){$d|Export-Csv -Path (Join-Path $csvDir (($sn -replace '[^a-zA-Z0-9_-]','_')+".csv")) -NoTypeInformation -Encoding UTF8}}
        Write-Host ("[+] CSVs saved to: "+$csvDir) -ForegroundColor Green
    }
}

# === MAIN ===
Add-Type -AssemblyName System.Web
Write-Host ""; Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "     BloodHound IR Analyzer - Incident Response Tool        " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan; Write-Host ""
$zipFullPath=(Resolve-Path $ZipPath).Path; $zipFileName=[System.IO.Path]::GetFileName($zipFullPath)
$bhData = Extract-BloodHoundData -Path $zipFullPath
$allResults = @{
    Stats=Analyze-UserStatistics -Data $bhData; DAEAMembers=Analyze-DomainAndEnterpriseAdmins -Data $bhData
    RecentUsers=Analyze-RecentlyCreatedUsers -Data $bhData -DaysBack 90; Kerberoastable=Analyze-KerberoastableUsers -Data $bhData
    ASREPRoastable=Analyze-ASREPRoastable -Data $bhData; UnconstrainedDeleg=Analyze-UnconstrainedDelegation -Data $bhData
    ConstrainedDeleg=Analyze-ConstrainedDelegation -Data $bhData; StalePasswords=Analyze-StalePasswords -Data $bhData -DaysStale 365
    NeverExpire=Analyze-NeverExpirePasswords -Data $bhData; InactiveAccounts=Analyze-InactiveAccounts -Data $bhData -DaysInactive 90
    HighValueTargets=Analyze-HighValueTargets -Data $bhData; NotInProtectedUsers=Analyze-NotInProtectedUsers -Data $bhData
    LAPSMissing=Analyze-LAPSStatus -Data $bhData; DomainControllers=Analyze-DomainControllers -Data $bhData
    OSBreakdown=Analyze-ComputerOS -Data $bhData; Trusts=Analyze-DomainTrusts -Data $bhData
    PasswordPolicy=Analyze-DomainPasswordPolicy -Data $bhData
    PasswordNotRequired=Analyze-PasswordNotRequired -Data $bhData
}
Write-Host ""; Write-Host "[*] Generating HTML report..." -ForegroundColor Cyan
$htmlContent = Build-HtmlReport -AllData $allResults -ZipFileName $zipFileName
[System.IO.File]::WriteAllText($OutputPath, $htmlContent, [System.Text.Encoding]::UTF8)
Write-Host ("[+] HTML report saved to: "+$OutputPath) -ForegroundColor Green
Export-ToXlsx -AllData $allResults -Path $XlsxPath
Write-Host ""; Write-Host "=== Quick Summary ===" -ForegroundColor Yellow
$s=$allResults.Stats; Write-Host ("  Total Users:              "+$s.TotalUsers); Write-Host ("  Enabled Users:            "+$s.EnabledUsers)
$enaDA=@($allResults.DAEAMembers|Where-Object{$_.Enabled -eq $true}).Count; Write-Host ("  Enabled DA/EA:            "+$enaDA) -ForegroundColor Red
Write-Host ("  Recently Created (90d):   "+$allResults.RecentUsers.Count); Write-Host ("  Kerberoastable:           "+$allResults.Kerberoastable.Count)
Write-Host ("  AS-REP Roastable:         "+$allResults.ASREPRoastable.Count); Write-Host ("  Unconstrained Deleg:      "+$allResults.UnconstrainedDeleg.Count)
Write-Host ("  Constrained Deleg:        "+$allResults.ConstrainedDeleg.Count); Write-Host ("  High-Value Targets:       "+$allResults.HighValueTargets.Count)
Write-Host ("  Inactive (90d):           "+$allResults.InactiveAccounts.Count); Write-Host ("  Not Protected Users:      "+$allResults.NotInProtectedUsers.Count)
Write-Host ("  Missing LAPS:             "+$allResults.LAPSMissing.Count); Write-Host ("  Stale Passwords (>1yr):   "+$allResults.StalePasswords.Count)
Write-Host ("  Pwd Not Required:         "+$allResults.PasswordNotRequired.Count)
Write-Host ("  Pwd Never Expires:        "+$allResults.NeverExpire.Count); Write-Host ("  Domain Controllers:       "+$allResults.DomainControllers.Count)
Write-Host ("  Domain Trusts:            "+$allResults.Trusts.Count); Write-Host ""
