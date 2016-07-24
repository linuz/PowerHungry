Function Invoke-AdminAccessFinder {
  <#
      .SYNOPSIS

        Locates hosts that a specific user or group identity has administrative access on. 
        Results are based on the CSV output from PowerView's Invoke-EnumerateLocalAdmin.
        Author: Dennis Maldonado (@DennisMald)
        License: BSD 3-Clause
        Required Dependencies: ActiveDirectory cmdlets,
        PowerView's Invoke-EnumerateLocalAdmin CSV Output File,  
        Optional Dependencies: None
        Minimum PowerShell Version = 3.0


      .DESCRIPTION

        Invoke-AdminAccessFinder is a supplement to PowerView's Invoke-EnumerateLocalAdmin that
        will search a list of hosts that the specified SamAccountName (user or group)
        has administrative access to. Invoke-AdminAccessFinder works by importing the CSV output from 
        PowerView's Invoke-EnumerateLocalAdmin function which should be generated ahead of time
        Invoke-AdminAccessFinder identifies the SamAccountName specified as well as it's group membership,
        recursively (with TokenGroups) so that it can search every single group the specified identity is a part of. 
        Invoke-AdminAccessFinder will return a list of hosts that the identity and any of it's group memberships
        have administrative access on.

        On first execution of Invoke-AdminAccessFinder, it will ask for the CSV file to import.
        Once imported, Invoke-AdminAccessFinder will not ask for the CSV file again for the duration 
        of the PowerShell session, unless the -Clean switch is specified.

        Thanks to @harmj0y for the random PowerShell tips and of course for PowerView
        <https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1>
    

      .PARAMETER SamAccountName

        The User or Group that you want the list of administrative access for. Accepts
        Pipeline input. If SamAccountName is a group, you must specific the -ObjectClass
        parameter with a value of 'group'.
        Defaults to current user if not specified


      .PARAMETER Server

        Specify the Domain Controller to query. You will want to query a domain controller for the 
        domain that the specific user/group is a member of.
        Defaults to current domain if not specified.

      .PARAMETER CheckDelegation

        Switch. Will check returned host for the "TrustedForDelegation" flag and adds it to
        the returned object. Results may be a bit slower as each host requires a domain query

      .PARAMETER Clean

        Switch. Will force Invoke-AdminAccessFinder to ask for a new CSV file on execution.
        This can be used to start searching a new dataset without having to restart the powershell
        session. Don't forget to remove this flag for subsequent executions unless desired.
    

      .EXAMPLE

        PS C:\> Invoke-AdminAccessFinder 

        Searches for hosts that the current user has access to. If no previous CSV file was specified during
        this PowerShell session, it will ask for one.

      .EXAMPLE

        PS C:\> Invoke-AdminAccessFinder -SamAccountName JohnDoe

        Searches for host that the 'JohnDoe' user has access to. 

      .EXAMPLE

        PS C:\> Invoke-AdminAccessFinder -SamAccountName JaneDoe -Server example.com

        Searches for host that the 'JaneDoe' user from the 'example.com' domain has access to.

      .EXAMPLE

        PS C:\> Invoke-AdminAccessFinder -SamAccountName "Domain Admins" -Clean

        Removes the exisiting data-set (previously imported CSV file) and will ask for a new CSV file to import.
        Will then search for hosts that the 'Domain Admins' group has admin access to.
        Note: Don't forget to remove this flag for subsequent executions unless it is desired

      .TODO

  #>
  
  [CmdletBinding()]
  param(

    # Since AD cmdlets output in non-standard ways, Alias and Parameter names needed to be switched
    [Parameter(Position=0, ValueFromPipelineByPropertyName=$True)]
    [ValidateNotNullOrEmpty()]
    [Alias('Identity')]
    [String]
    $SamAccountName = $Env:USERNAME,
        
    [ValidateNotNullOrEmpty()]
    [String]
    $Server = $Env:USERDNSDOMAIN,
        
    [Switch]
    $CheckDelegation,

    [Switch]
    $Clean
  )
    
  begin {
    # Make all errors a terminating error
    $erroractionPreference = 'stop'

    #Allow other function see the CheckDelegation switch
    $Script:CheckDelegation = $CheckDelegation

    # If database does not exist or -Clean is specified, import the CSV into a new database
    if ((!$Global:LocalAdminHashTable -AND !$Global:LocalAdminHashTableName) -OR $Clean) {
      Invoke-ImportPowerViewAdminsCSV $CSVFilePath
    }
  }
  
  process {
    # Check if passing in data from Pipeline
    if ($PSCmdlet.MyInvocation.ExpectingInput) {
      $InputObject = $_
      Write-Verbose "Searching $($InputObject.SamAccountName) from Pipeline"
      Get-EffectiveGroups -Server $Server -SamAccountName $SamAccountName | ForEach-Object {
        $_ | Search-LocalAdmins
      }
    }
        
    elseif ($SamAccountName) {
      Write-Verbose "Searching $SamAccountName from the -SamAccountName argument value"
      Get-EffectiveGroups -Server $Server -SamAccountName $SamAccountName | ForEach-Object {
        $_ | Search-LocalAdmins
      }
    }
  }
}

Function Get-SamAccountNameFromSID {

  <#

      .DESCRIPTION
        Converts the SID of an AD object to it's SamAccountName value
  #> 

  try {
    $SamAccountName = New-Object System.Security.Principal.SecurityIdentifier($args[0])
    $SamAccountName = $SamAccountName.Translate([System.Security.Principal.NTAccount]).value.Split('\')[1]
    return $SamAccountName
  }       
  catch {
    Write-Verbose "WARNING: Can not resolve name for SID: $TokenSID"
    return $null
  }  
}  
Function Invoke-ImportPowerViewAdminsCSV {

  <#

      .DESCRIPTION

        Imports PowerView's Invoke-EnumerateLocalAdmin CSV Output File. Checks to see if dataset
        already exists and removes it if so. Performs cleanup and garbage collection.
  #>
  
  # Remove the variables first if they exist
  if ($Global:LocalAdminHashTable) {
    Write-Verbose 'Removing the old database'
    Remove-Variable -Scope global LocalAdminHashTable
  }

  if ($Global:LocalAdminHashTableName) {
    Remove-Variable -Scope global LocalAdminHashTableName
  }

  Write-Verbose 'Prompting for CSV file'
  $CSVFilePath = (read-host 'Please enter the Local Admin CSV File Path: ')
  if ($CSVFilePath -EQ '') {
    Write-Error 'Invalid File Path. Empty string supplied'
    Break
  }
  if (!(Test-Path $CSVFilePath)) {
    Write-Error "Invalid File Path of $CSVFilePath"
    Break
  }

  Write-Verbose "Using $CSVFilePath"
  Write-Verbose 'Checking if CSV file contains the proper headers' 
  try {    
    $CSVHeaders = ((Get-Content $CSVFilePath | Select-Object -First 2).Split(',')) -replace '"'
  }
  catch {
    $_.Exception.Message
    $_.Exception.ItemName
    Break
  }
  if (!($CSVHeaders.contains('Server') -and $CSVHeaders.contains('AccountName') -and $CSVHeaders.contains('SID'))) {
    Write-Error "CSV file is not valid. Expecting CSV file from 'PowerView's Invoke-EnumerateLocalAdmin -OutFile' parameter"
    break
  }

  $Global:LocalAdminHashTableName = $CSVFilePath
  Write-Output "Importing CSV File: $Global:LocalAdminHashTableName"
  $LocalAdminCSV = Import-CSV $Global:LocalAdminHashTableName
  Write-Verbose "Copying $Global:LocalAdminHashTableName to memory (This may take a minute or two...)"
  $Global:LocalAdminHashTable = $LocalAdminCSV | Group-Object -AsHashTable -AsString -Property SID
  Write-Verbose "The $Global:LocalAdminHashTableName CSV file has been imported into a hash table in memory."
  Write-Verbose 'Performing cleanup and garbage collection'
  Write-Output 'Import complete'
  Remove-Variable LocalAdminCSV
  [System.GC]::collect() 
}

Function Get-EffectiveGroups {

  <#

      .DESCRIPTION

        Recursively enumerate groups a specific identity is a member of by pulling TokenGroups from AD.
  #>

  [CmdletBinding()]
  param(
  
    [String]
    $SamAccountName,
        
    [String]
    $Server,

    [Switch]
    $NoSelfIdentity
  )

  Write-Verbose "Searching $SamAccountName"
        
  # Allow searching for users or groups
  $ADObject = Get-ADObject -Server $Server -Properties objectSid, SamAccountName -Filter {SamAccountName -EQ $SamAccountName}
  if (!$ADObject) {
    Write-Error "$SamAccountName was not found on $Server"
    break
  }

  Write-Verbose "Getting TokenGroups with Get-ADObject for $SamAccountName"
  if (!$NoSelfIdentity) {
    $SelfIdentityObject = New-Object PSObject
    $SelfIdentityObject | Add-Member NoteProperty 'SamAccountName' $ADObject.SamAccountName
    $SelfIdentityObject | Add-Member NoteProperty 'ObjectClass' $AdObject.ObjectClass
    $SelfIdentityObject | Add-Member NoteProperty 'objectSID' $ADObject.objectSID
    $SelfIdentityObject | Add-Member NoteProperty 'IdentitySearched' $SamAccountName
    $SelfIdentityObject
  }

  # Return Identity's TokenGroups (unrolled nested groups) as objects
  Write-Verbose "Returning Identity's TokenGroups"
      
  Get-ADObject -Server $Server -SearchScope Base -SearchBase $ADObject.DistinguishedName -Filter * -Properties tokenGroups | Select-Object -ExpandProperty TokenGroups| ForEach {
    $TokenGroupName = Get-SamAccountNameFromSID $_
    $GroupObject = New-Object PSObject
    $GroupObject | Add-Member NoteProperty 'SamAccountName' $TokenGroupName
    $GroupObject | Add-Member NoteProperty 'ObjectClass' 'group'
    $GroupObject | Add-Member NoteProperty 'objectSID' $_
    $GroupObject | Add-Member NoteProperty 'IdentitySearched' $SamAccountName
    $GroupObject    
  }
}
    
Function Search-LocalAdmins {

  <#

    .DESCRIPTION

      Searches the imported spreadsheet for the user/group SamAccountName specified

  #>
  
   
  [CmdletBinding()]
  param(

    [Parameter(ValueFromPipelineByPropertyName=$True)]
    [String[]]
    $SamAccountName,

    [Parameter(ValueFromPipelineByPropertyName=$True)]
    [String[]]
    $ObjectClass,

    [Parameter(ValueFromPipelineByPropertyName=$True)]
    [String]
    $objectSID,

    [Parameter(ValueFromPipelineByPropertyName=$True)]
    [String]
    $IdentitySearched

  )
    
  Write-Verbose "Searching the SID: $objectSID for $IdentitySearched"
  $SIDResults = $Global:LocalAdminHashTable[$objectSID].Server
    
  if ($SIDResults) {
    $SIDResults | ForEach-Object {
      $ServerObject = New-Object PSObject
      $ServerObject | Add-Member NoteProperty 'DNSHostName' $_
      $ServerObject | Add-Member NoteProperty 'IdentitySearched' $IdentitySearched
      $ServerObject | Add-Member NoteProperty 'SamAccountName' ($SamAccountName|ForEach-Object {$_})
      $ServerObject | Add-Member NoteProperty 'ObjectClass' ($ObjectClass|ForEach-Object {$_})
      #$ServerObject | Add-Member NoteProperty 'ObjectSID' $objectSID

      # Check if returned boxes for the "TrustedForDelegation" flag
      if ($Script:CheckDelegation) {
        $ServerName = $ServerObject.DNSHostName.split('.')[0]
        Write-Verbose "Checking $ServerName for the `"TrustedForDelegation`" flag"
        try {
          if ((Get-ADComputer -Server $Server -Identity $ServerName -Properties TrustedForDelegation).TrustedForDelegation) {
            $ServerObject | Add-Member NoteProperty 'TrustedForDelegation' $True
          }
          else {
            $ServerObject | Add-Member NoteProperty 'TrustedForDelegation' $False
          }
        }
        catch {
          Write-Verbose "Can not find the host $ServerName"  
        }   
      }
      $ServerObject
    }
  }
    
  else {
    Write-Debug "SID: $objectSid not found in database."
  }
}
