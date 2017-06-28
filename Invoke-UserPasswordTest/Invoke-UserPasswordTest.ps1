Function Invoke-UserPasswordTest {
  <#
      .SYNOPSIS

        Tests AD users with passwords of their username
        Author: Dennis Maldonado <dennismald@gmail.com>
        Optional Dependencies: ActiveDirectory cmdlets
        Minimun PowerShell Version = 3.0

      .DESCRIPTION

        Tests a specified username with a password that matches their username. You can specify a username via the
        SamAccountName parameter or you can pass this into the pipeline.

      .PARAMETER SamAccountName

        Specify the user to test. This is accepted in the pipeline from other commands such as 'Get-ADUser' or
        'Get-ADGroupMember'

      .EXAMPLE

        PS C:\> Invoke-UserPasswordTest -SamAccountName JohnDoe

        Test one user for the password of their username

      .EXAMPLE
        
        PS C:\> Get-ADUser -Filter * | Invoke-UserPasswordTest

        Test all users in the domain for passwords of their username

      .EXAMPLE
        
        PS C:\> Get-ADUser -Filter * | Invoke-UserPasswordTest -Verbose | Export-CSV FoundUserPasswords.csv

        Test all users in the domain for passwords of their username with verbose output, saving results to a CSV file
  #>

    [CmdletBinding()]
    param(

        [Parameter(Position=0, ValueFromPipelineByPropertyName=$True)]
        [ValidateNotNullOrEmpty()]
        [Alias('Username')]
        [String]
        $SamAccountName
    )

    process {
   
        if ($SamAccountName -eq "") {
            Write-Host "No Username Specified"
            Return
        }

        if (! $SamACcountName.EndsWith("$")) {

            # Set Username to test
            $Username = $SamAccountName

            # Set Password as the Username
            $Password = $Username
    
            Write-Verbose "Testing Username: $Username with Password: $Password"

            if ((new-object DirectoryServices.DirectoryEntry "",$Username,$Password).psbase.name -ne $null) {
                $ResultsObject = New-Object PSObject
                $ResultsObject | Add-Member NoteProperty 'Username' $Username
                $ResultsObject | Add-Member NoteProperty 'Password' $Password
                $ResultsObject
            }

            else {
                Write-Verbose "Invalid password for Username: $Username"
            }
        }
    }
}