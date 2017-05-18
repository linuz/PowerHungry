function Get-AllTrusts {

     <#
            .SYNOPSIS

                Takes a domain or forest as an input (defaults the current domain) and lists all the tursts
                the domain/forest has with other domains/forests. Will also output status of SIDFiltering
                and SelectiveAuthorization.
                Author: Dennis Maldonado (@DennisMald)
                License: BSD 3-Clause
                Required Dependencies: None
                Optional Dependencies: None
                Minimum PowerShell Version = 2.0
         
             .DESCRIPTION

                Get-AllTrusts will list the trusts for the inputted or current Domain/Forest and will
                output whether SID Filtering and Selective Authorization are enabled on the trust. 
            
                If SIDFiltering is disabled, attackers can perform a SIDHistory attack to gain DA/EA privilleges from
                one Domain/Forest to another Domain/Forest. See more on the attack here:
                https://adsecurity.org/?p=1640
        
            .PARAMETER Domain

                The Domain or Forest you want to list out trust information for. Will default to the user's corrent
                domain if one is not specified.

            .EXAMPLE
            
                PS C:\> Get-AllTrusts
                
                    Will grab the trust information for the domain the current user is a member of
            
            .EXAMPLE
            
                PS C:\> Get-AllTrusts -Domain ABC.LOCAL | ft

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

    function Boolean-IsForest {
        param(
            [String]
            $Domain
        )

        $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
        try {
            $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
        }
        catch {
            Write-Error "Could not contact Domain: $Domain"
            return
        }
        if (($DomainObject | Select-Object Parent).Parent -EQ $NULL) {
            $True
        } 
        else {
            $False
        }
    }

    $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $Domain)
    $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
    if (Boolean-IsForest -Domain $Domain) {
        $ForestTrusts = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext).GetAllTrustRelationships()
        $ForestTrusts | ForEach {
            try {
                $SidFilteringStatus = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext).GetSidFilteringStatus($_.TargetName)
                $SelectiveAuthenticationStatus = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext).GetSelectiveAuthenticationStatus($_.TargetName)
                $Trust = New-Object PSObject
                $Trust | Add-Member NoteProperty 'SourceName' $_.SourceName
                $Trust | Add-Member NoteProperty 'TargetName' $_.TargetName
                $Trust | Add-Member NoteProperty 'TrustType' $_.TrustType
                $Trust | Add-Member NoteProperty 'TrustDirection' $_.TrustDirection
                $Trust | Add-Member NoteProperty 'SidFilteringStatus' $SidFilteringStatus
                $Trust | Add-Member NoteProperty 'SelectiveAuthenticationStatus' $SelectiveAuthenticationStatus
                $Trust
            }
            catch {
                Write-Error $_
            }
        }
    }
    
    $DomainTrusts = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext).GetAllTrustRelationships()
    $DomainTrusts | ForEach {
        try {
            $SidFilteringStatus = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext).GetSidFilteringStatus($_.TargetName)
            $SelectiveAuthenticationStatus = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext).GetSelectiveAuthenticationStatus($_.TargetName)
                $Trust = New-Object PSObject
                $Trust | Add-Member NoteProperty 'SourceName' $_.SourceName
                $Trust | Add-Member NoteProperty 'TargetName' $_.TargetName
                $Trust | Add-Member NoteProperty 'TrustType' $_.TrustType
                $Trust | Add-Member NoteProperty 'TrustDirection' $_.TrustDirection
                $Trust | Add-Member NoteProperty 'SidFilteringStatus' $SidFilteringStatus
                $Trust | Add-Member NoteProperty 'SelectiveAuthenticationStatus' $SelectiveAuthenticationStatus
                $Trust
            }
        catch {
            Write-Error $_
        }
    }
}
