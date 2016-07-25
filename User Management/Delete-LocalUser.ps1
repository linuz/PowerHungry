Function Delete-LocalUser {
    <#
        .SYNOPSIS
            Deletes a local user from the specified computer (Without using net.exe)
            Author: Dennis Maldonado (@DennisMald)
            License: BSD 3-Clause
            Required Dependencies: None  
            Optional Dependencies: None
            Minimum PowerShell Version = 2.0
            
        .DESCRIPTION
            Delete-LocalUser will delete a local user from the specified computer, using ADSI. 
            You must have elevated rights to the target computer in order to do this.
            Delete-LocalUser is useful for bypassing end-point monitoring alerts that flag on net.exe usage.
            
        .PARAMETER ComputerName
            Specify the computer to target.
            Defaults to current computer
            
        .PARAMETER Username
            Name of the user to delete.
            Defaults to 'TempUser'

        .EXAMPLE
        
        PS C:> Delete-LocalUser
        
        Deletes the local 'TempUser' from the current computer
        
        .EXAMPLE
        
        PS C:> Add-LocalAdmin -ComputerName Server1.example.com -Username JohnDoe
        
        Deletes the local 'JohnDoe' from the Server1.example.com
        
        
    #>
    
    [CmdletBinding()]
    param(

        # Since AD cmdlets output in non-standard ways, Alias and Parameter names needed to be switched
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $env:COMPUTERNAME,
        
        [Parameter(Position=0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Username = "TempUser"
        
    )

    $ADSIComp = [adsi]"WinNT://$ComputerName"
    $ADSIComp.Delete('User', $Username)
   
}
