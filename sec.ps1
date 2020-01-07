## Run as admin with execution policy bypass ##
## Open PS as admin and then type: Set-ExecutionPolicy bypass

## Check privs 
if (-NOT([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning -Message "The script requires elevation. Run as admin"
    break
}

function reboot_required {
    $CBSRebootKey = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction Ignore
    $WURebootKey = Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction Ignore
    if (($CBSRebootKey -ne $null) -OR ($WURebootKey -ne $null)) {
        Write-Warning "Reboot is required" 
    }
    else {
        Write-Warning "Reboot is not required but it is suggested to do so in order for the modification to take place" 
    }
}

## Identify Windows build
$WindowsBuild = (Get-WmiObject -Class Win32_OperatingSystem).BuildNumber

if ($WindowsBuild -eq "18362"){
    Write-Host "`nWindows Build seems to be 1903."
}
elseif ($WindowsBuild -lt "18362") {
    Write-Warning "`nUpdate Windows to build 1903 before running this script"
}
else {
    Write-Host "`nWindows build seems to be higher than 1903."
}

## Build Report table
$tabName = "Report"
$table = New-Object system.Data.DataTable "$tabName"
$col1 = New-Object system.Data.DataColumn Name,([string])
$col2 = New-Object system.Data.DataColumn Result,([string])
$table.columns.add($col1)
$table.columns.add($col2)

## Disable IPV6 on Network adapter
try{
    $ipv6 = Get-NetAdapterBinding -Name Ethernet -ComponentID ms_tcpip6
    if($ipv6.Enable -eq "True"){
        Disable-NetAdapterBinding -Name $ipv6.Name -ComponentID $ipv6.ComponentID
        $row = $table.NewRow()
        $row.Name = "Disable IPv6"
        $row.Result = "Success"
        $table.Rows.Add($row)
    }
    else{
        $row = $table.NewRow()
        $row.Name = "Disable IPv6"
        $row.Result = "Success"
        $table.Rows.Add($row)
    }
}
catch{
    $row = $table.NewRow()
    $row.Name = "Disable IPv6"
    $row.Result = "Failed"
    $table.Rows.Add($row)
}

## Disable NetBIOS over TCP
try{
    $key = "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
    $interfaces = Get-ChildItem $key
    $interfaces = $interfaces.Name | ForEach-Object {$_.split("\")[7]}
    for($i=0; $i -lt $interfaces.count; $i++){
        Set-ItemProperty -Path "$key\$($interfaces[$i])" -Name "NetbiosOptions" -Value 2
    }
    $row = $table.NewRow()
    $row.Name = "Disable Netbios TCP"
    $row.Result = "Success"
    $table.Rows.Add($row)
}
catch{
    $row = $table.NewRow()
    $row.Name = "Disable Netbios TCP"
    $row.Result = "Failed"
    $table.Rows.Add($row)
}

## Disable WPAD
$wpad = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' -Name WpadOverride -ErrorAction Ignore
if ($wpad -eq $null){
    try{
        New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' -Name WpadOverride -Value 1
        $row = $table.NewRow()
        $row.Name = "Disable WPAD"
        $row.Result = "Success"
        $table.Rows.Add($row)
    }
    catch{
        Write-Host "An error occured while trying to disable the WPAD feature" -BackgroundColor Yellow -ForegroundColor Red
        $row = $table.NewRow()
        $row.Name = "Disable WPAD"
        $row.Result = "Failed"
        $table.Rows.Add($row)
    }
}
else{
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' -Name WpadOverride -Value 1
    $row = $table.NewRow()
    $row.Name = "Disable WPAD"
    $row.Result = "Success"
    $table.Rows.Add($row)
}

## Array of registry keys to modify
$items = @(
    @('HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient', 'EnableMulticast', 0, 'Disable Multicast name resolution'),
    @('HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters', 'RequireSecuritySignature', 1, 'Activate Client: Digitally sign communications (always)'),
    @('HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters', 'EnableSecuritySignature', 1, 'Activate Client: Digitally sign communications (if server agrees)'),
    @('HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters', 'requiresecuritysignature', 1, 'Activate Server: Digitally sign communications (always)'),
    @('HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters', 'enablesecuritysignature', 1, 'Activate Server: Digitally sign communications (if client agrees)'),
    @('HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest', 'Negotiate', 0, 'Disable WDigest (Negotiate)'),
    @('HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest', 'UseLogonCredential', 0, 'Disable WDigest (UseLogonCredential)'),
    @('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'RunAsPPL', 1, 'Enable LSA protection'),
    @('HKLM:\System\CurrentControlSet\Control\Lsa', 'DisableDomainCreds', 1, 'Disable saved passwords'),
    @('HKLM:\System\CurrentControlSet\Control\Lsa', 'NoLmHash', 1, 'Disable LM'),
    @('HKLM:\System\CurrentControlSet\Control\Lsa', 'DisableRestrictedAdmin', 0, 'Disable RDP Admin password in LSASS'),
    @('HKLM:\System\CurrentControlSet\Control\Lsa', 'DisableRestrictedAdminOutboundCreds', 1, 'Disallow network authentication from inside the system'),
    @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 'CachedLogonsCount', 0, 'Disable credentials caching')
)

## Disable items
foreach ($item in $items){
    try{
        $key = Get-ItemProperty -Path $item[0] -Name $item[1] -ErrorAction Ignore
        if (!$key){
            New-ItemProperty -Path $item[0] -Name $item[1] -Value $item[2]
            $row = $table.NewRow()
            $row.Name = $item[3]
            $row.Result = "Success"
            $table.Rows.Add($row)
        }
        elseif ($key){
            Set-ItemProperty -Path $item[0] -Name $item[1] -Value $item[2]
            $row = $table.NewRow()
            $row.Name = $item[3]
            $row.Result = "Success"
            $table.Rows.Add($row)
        }
    }
    catch{
        Write-Host "An error occured with this command: $item" -BackgroundColor Yellow -ForegroundColor Red
        $row = $table.NewRow()
        $row.Name = $item[3]
        $row.Result = "Failed"
        $table.Rows.Add($row)
    }
}

$table | format-table -AutoSize

## Check if reboot is required
reboot_required
