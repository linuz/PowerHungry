Function Add-LocalAdmin {
    <#
        .SYNOPSIS
            Adds a user to the local administrator group for the specified computer. (Without using net.exe)
            Author: Dennis Maldonado (@DennisMald)
            License: BSD 3-Clause
            Required Dependencies: None  
            Optional Dependencies: None
            Minimum PowerShell Version = 2.0
            
        .DESCRIPTION
            Add-LocalAdmin will create a specified user and adds it to the local administrators group 
            for the specific computer, using AdsI. You must have elevated rights to the target computer in 
            order to do this.
            Add-LocalAdmin is useful for bypassing end-point monitoring alerts that flag on net.exe usage.
            
        .PARAMETER ComputerName
            Specify the computer to target.
            Defaults to current computer
            
        .PARAMETER Username
            Name of the user to add.
            Defaults to 'TempUser'
            
        .PARAMETER Password
            Password for the user being added
            Defaults to 'Password@1'
            
        .EXAMPLE
        
        PS C:> Add-LocalAdmin
        
        Creates a new user called 'TempUser' with the password of 'Password@1' on the current computer
        and adds it to the local Administrators group.
        
        .EXAMPLE
        
        PS C:> Add-LocalAdmin -ComputerName Server1.example.com -Username JohnDoe -Password Password@2
        Creates a new user called 'JohnDoe' with the password of 'Password@2' to server1.example.com
        and adds it to the local Administrators group.
        
        
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
        $Username = "TempUser",
        
        [ValidateNotNullOrEmpty()]
        [String]
        $Password = "Password@1"
    )

    $Group = "Administrators"
    $ADSIUser = [adsi]"WinNT://$ComputerName"
    $NewUser = $ADSIUser.Create('User', $Username)
    $NewUser.SetPassword($Password)
    $NewUser.SetInfo()

    $ADSIGroup = [ADSI]"WinNT://$ComputerName/$Group,group"
    $ADSIGroup.add("WinNT://$ComputerName/$Username,user")
   
}
