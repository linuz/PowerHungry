Function Search-LocalAdmins {
  <#

      .SYNOPSIS

        Finds boxes an identity has local admin on, based on the CSV output from
        PowerView's Invoke-EnumerateLocalAdmin.
        Author: Dennis Maldonado (@DennisMald)
        License: BSD 3-Clause
        Required Dependencies: PowerView's Invoke-EnumerateLocalAdmin CSV Output
        Optional Dependencies: None
        Minimum PowerShell Version = 3.0

      .DESCRIPTION

        Search-LocalAdmins will load the CSV file of Local Admins into memory.
        (CSV file comes from PowerView's Invoke-EnumerateLocalAdmin CSV Output)
        Search-LocalAdmins will then take in a SID value via parameter or pipeline
        and will search for it in the CSV file.

        Thanks to @harmj0y for his feedback and of course for PowerView
        <https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1>

      .PARAMETER ImportCSV
      
        Name/Path of the CSV file to import. Expecting Powerview's 
        Invoke-EnumerateLocalAdmin CSV Output file.
        (Ex: PowerView.ps1: Invoke-EnumerateLocalAdmin -OutFile admins.csv)

        The -ImportCSV parameter only needs to be run once per PowerShell session
        unless you want to load up a new list into memory.

        The -ImportCSV paramete may take a few minutes to load initially depending
        on the size of the CSV file. 
        
        I have built in a lot of memory managment to help with load times
        and memory usage. The -ImportCSV parameter will overwrite any 
        previous -ImportCSV data and will clean up after itself

      .PARAMETER SID

      Mandatory.

      SID of object to search CSV file for. Can be a User or Group.

      Accepted as a parameter or through a Pipeline

      .EXAMPLE
      
        PS C:\> Find-LocalAdmin -ImportCSV c:\files\admins.csv -SID S-1-5-21-1004336348-1177238915-682003330-512

        Initally load admin.csv file into memory and search it for the specified SID
        Note: You do not need to use -ImportCSV every time.
      
      .EXAMPLE
      
        PS C:\> Find-LocalAdmin -SID S-1-5-21-1004336348-1177238915-682003330-512

        Search for SID in the CSV file that is loaded in memory.

      .EXAMPLE
      
        PS C:\> Get-ADUser -Identity "JohnDoe" | Find-LocalAdmin
        
        Will pass JohnDoe's SID through the pipeline to Find-LocalAdmin and search for it
        in the CSV file loaded in memory
      
      .TODO

        - Allow for Identity instead of just SID
        - Output to objects
        - Progress indicator for -ImportCSV
        - Add checking for proper CSV format
        - Search for Identity SID in the HashTable as well

  #>
  
  [CmdletBinding()]
    param(
        [String]
        $ImportCSV,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String[]]
        $SID
    )

    # Lots of memory management in here, thus lots of verbosity with the -Verbose flag
    if ($ImportCSV) {
        Write-Verbose 'Parameter -ImportCSV Present'
        # Check if $Global:LocalAdminHashTable already exists
        Write-Verbose "Checking if `$Global:LocalAdminHashTable already exist"
        if ($Global:LocalAdminHashTable) {
            Write-Verbose "Variable `$Global:LocalAdminHashTable exist, prompting to remove"
            Remove-Variable -Scope Global -Confirm LocalAdminHashTable
        }
        Write-Verbose "Importing CSV File: $ImportCSV"
        $LocalAdminCSV = Import-CSV $ImportCSV
        Write-Verbose "Writing to `$Global:LocalAdminHashTable varaible (This may take a minute or two...)"
        $Global:LocalAdminHashTable = $LocalAdminCSV | Group-Object -AsHashTable -AsString -Property SID
        Write-Verbose 'CSV file has been imported into a hash table. You do not need to do this again'

        # Cleanup and garbage collection
        Write-Verbose 'Cleaning up variables and collecting garbage'
        Remove-Variable LocalAdminCSV
        [System.GC]::collect()
    }
    
    if ($SID) {
      Write-Verbose "Searching SID: $SID"
      try {
        $SIDResults = $Global:LocalAdminHashTable[$SID].Server
        if ($SIDResults) {
          $SIDResults
        }
        
        else {
          Write-Verbose "SID: $SID not found"
        }
      }
      
      catch {
        Write-Error 'No CSV file currently imported. Use "-ImportCSV <CSV File>"'
        Write-Warning 'You will only need to run -ImportCSV once per PowerShell session'
      }
    }
    
    else {
      Write-Warning 'No SID supplied. Doing nothing else.'
    }
}