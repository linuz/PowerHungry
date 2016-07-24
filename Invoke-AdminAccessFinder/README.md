# PowerHungry
**Twitter: [@DennisMald](https://twitter.com/DennisMald)**

Invoke-AdminAccessFinder
----------------
Invoke-AdminAccessFinder is a supplement to PowerView's Invoke-EnumerateLocalAdmin that will search a list of hosts that the specified SamAccountName (user or group) has administrative access to. Invoke-AdminAccessFinder works by importing the CSV output from  PowerView's Invoke-EnumerateLocalAdmin function which should be generated ahead of time Invoke-AdminAccessFinder identifies the SamAccountName specified as well as it's group membership, recursively (with TokenGroups) so that it can search every single group the specified identity is a part of.  Invoke-AdminAccessFinder will return a list of hosts that the identity and any of it's group memberships have administrative access on.

On first execution of Invoke-AdminAccessFinder, it will ask for the CSV file to import. Once imported, Invoke-AdminAccessFinder will not ask for the CSV file again for the duration of the PowerShell session, unless the -Clean switch is specified.

Thanks to @harmj0y for the random PowerShell tips and of course for PowerView <https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1>

Requirements:
----------------
**[PowerView's Invoke-EnumerateLocalAdmin](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon) CSV Output**:

    PS C:\> Invoke-EnumerateLocalAdmin -Threads 100 -OutFile localadmins.csv
    
or

    PS C:\> Invoke-EnumerateLocalAdmin -Threads 100 | Export-CSV localadmins.csv

**[Active Directory Cmdlets](https://technet.microsoft.com/en-us/library/ee617195.aspx)**:

    PS C:\> Import-Module ActiveDirectory
	
Example Usage:
----------------
Searches for hosts that the current user has access to. If no previous CSV file was specified during this PowerShell session, it will ask for one.

    PS C:\> Invoke-AdminAccessFinder 
    
Searches for host that the 'JohnDoe' user has access to. 

    PS C:\> Invoke-AdminAccessFinder -SamAccountName JohnDoe
	
Uses 'Get-AdGroupMember' to get members of the 'Domain Admins' group and checks each member to see what hosts they have access to

    PS C:\> Get-ADGroupMember "Domain Admins" | Invoke-AdminAccessFinder
