# PowerHungry
**Twitter: [@DennisMald](https://twitter.com/DennisMald)**

Invoke-AdminAccessFinder
----------------
Invoke-AdminAccessFinder is a supplement to PowerView's Invoke-EnumerateLocalAdmin that will search a list of hosts that the specified SamAccountName (user or group) has administrative access to. Invoke-AdminAccessFinder works by importing the CSV output from  PowerView's Invoke-EnumerateLocalAdmin function which should be generated ahead of time Invoke-AdminAccessFinder identifies the SamAccountName specified as well as it's group membership, recursively (with TokenGroups) so that it can search every single group the specified identity is a part of.  Invoke-AdminAccessFinder will return a list of hosts that the identity and any of it's group memberships have administrative access on.

On first execution of Invoke-AdminAccessFinder, it will ask for the CSV file to import. Once imported, Invoke-AdminAccessFinder will not ask for the CSV file again for the duration of the PowerShell session, unless the -Clean switch is specified.

Thanks to [@harmj0y](https://twitter.com/harmj0y) for the random PowerShell tips and of course for PowerView <https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1>

Purpose:
----------------
I built this script to help save time during red team assessments against an Active Directory network. We wanted a way to target specific users and servers during an assessment and avoid just spraying the network looking for any box we can get access to.

This script saves time by allowing us to specifically target boxes we have admin access on. For example, if we gain access to the "EXAMPLE\JohnDoe" domain account from a compromised host, we can use Invoke-AdminAccessFinder to find out which hosts EXAMPLE\JohnDoe has administrative access on, and go target those hosts directory instead of spraying his creds across the entire network.

Requirements:
----------------
**[PowerView's Invoke-EnumerateLocalAdmin](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon) CSV Output**:

Invoke-EnumerateLocalAdmin will query all active machines on a network for it's local administrators. This takes some time but only needs to be done once so doing this ahead of time can be advantageous.

You will need to generate a CSV file from Invoke-EnumerateLocalAdmin's output if you have not done so already.

    PS C:\> Invoke-EnumerateLocalAdmin -Threads 100 -OutFile localadmins.csv
    
or

    PS C:\> Invoke-EnumerateLocalAdmin -Threads 100 | Export-CSV localadmins.csv

**[Active Directory cmdlets](https://technet.microsoft.com/en-us/library/ee617195.aspx)**:

The ActiveDirectory cmdlets are currently being used by this script to perform some of the domain controller queries. There is a plan to remove this dependency in the future.

    PS C:\> Import-Module ActiveDirectory

Note: Windows 7 users will need the Remote Server Administration Tools (RSAT) to use the ActiveDirectory cmdlets

Example Usage:
----------------
Searches for hosts that the current user has access to. If no previous CSV file was specified during this PowerShell session, it will ask for one.

    PS C:\> Invoke-AdminAccessFinder 
    
Searches for host that the 'JohnDoe' user has access to. 

    PS C:\> Invoke-AdminAccessFinder -SamAccountName JohnDoe
	
Uses 'Get-AdGroupMember' to get members of the 'Domain Admins' group and checks each member to see what hosts they have access to

    PS C:\> Get-ADGroupMember "Domain Admins" | Invoke-AdminAccessFinder
