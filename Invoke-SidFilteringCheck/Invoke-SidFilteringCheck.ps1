Function Invoke-SidFilteringCheck {
    <#
        .SYNOPSIS

            Takes a domain or forest as an input (defaults the current domain) and lists out trust information
            with other domains as well as if SID Filtering is enabled or not.
            Author: Dennis Maldonado (@DennisMald)
            License: BSD 3-Clause
            Required Dependencies: ActiveDirectory cmdlets 
            Optional Dependencies: None
            Minimum PowerShell Version = 2.0
         
         .DESCRIPTION

            Invoke-SidFilteringCheck will list the trusts for the inputted or current Domain/Forest and will
            output whether SIDFiltering is enabled or disabled on that trust. 
            
            If SIDFiltering is disabled, attackers can perform a SIDHistory attack to gain DA/EA privilleges from
            one Domain/Forest to another Domain/Forest. See more on the attack here:
            https://adsecurity.org/?p=1640

            SIDFiltering Trust Status information for reference:
                Forest Trust - if SIDFilteringForestAware is True, SIDFiltering is disabled on the forest trust
                External Trust - if SIDFilteringQuarantined is False, SIDFiltering is disabled on the external trust
        
        .PARAMETER Domain

            The Domain or Forest you want to list out trust information for. Will default to the user's corrent
            domain if one is not specified.

        .EXAMPLE
            
            PS C:\> Invoke-SidFilteringCheck
                
                Will grab the trust information for the domain the current user is a member of
            
        .EXAMPLE
            
            PS C:\> Invoke-SidFilteringCheck ABC.LOCAL | ft

                Will grab the trust information for all the trusts with ABC.LOCAL Domain/Forest. You can pipe the results
                to Format-Table (ft) for easier reading
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position=0, ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain = $Env:USERDNSDOMAIN
    )

    process {
        Write-Verbose "Getting Trust for $Domain"
        ActiveDirectory\Get-ADTrust -Filter * -Server $Domain | ForEach-Object {
        $SidFilteringDisabled = $False
            if ($_.ForestTransitive) {
                $Type = "Forest"
                if ($_.SIDFilteringForestAware) {
                    $SidFilteringDisabled = $True
                }
            }
            elseif (-not ($_.ForestTransitive)) {
                $Type = "Shortcut or External"
                if (-not ($_.SIDFilteringQuarantined) -and (-not ($_.IntraForest))) {
                    $SidFilteringDisabled = $True
                }
            }

            $DomainObject = New-Object PSObject
            $DomainObject | Add-Member NoteProperty 'Trusting Domain' $Domain
            $DomainObject | Add-Member NoteProperty 'Trusted Domain' $_.Name
            $DomainObject | Add-Member NoteProperty 'Direction' $_.Direction
            $DomainObject | Add-Member NoteProperty 'Type' $Type
            $DomainObject | Add-Member NoteProperty 'SidFilteringDisabled' $SidFilteringDisabled
            $DomainObject | Add-Member NoteProperty 'SelectiveAuthentication' $_.SelectiveAuthentication
            $DomainObject
        }
    }
}
