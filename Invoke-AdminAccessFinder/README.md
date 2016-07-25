# PowerHungry
**Twitter: [@DennisMald](https://twitter.com/DennisMald)**

Invoke-AdminAccessFinder
----------------
Invoke-AdminAccessFinder is a supplement to PowerView's Invoke-EnumerateLocalAdmin. Invoke-AdminAccessFinder will search a list of hosts that the specified user/group has administrative access to. Invoke-AdminAccessFinder gets it's dataset by importing the CSV output from  PowerView's Invoke-EnumerateLocalAdmin function. Invoke-AdminAccessFinder identifies the security group membership for the user/group, recursively (with [TokenGroups] (https://msdn.microsoft.com/en-us/library/ms680275(v=vs.85).aspx)) and will return a list of hosts that the user/group and any of it's group memberships have administrative access on.

On first execution of Invoke-AdminAccessFinder, you will be prompted to import the CSV file. Invoke-AdminAccessFinder will only ask for the CSV once per PowerShell session, unless the -Clean switch is specified.

Thanks to [@harmj0y](https://twitter.com/harmj0y) for the some PowerShell tips and of course for PowerView <https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1>

Purpose:
----------------
I built this script to help save time during red team assessments against an Active Directory network. I wanted a way to target specific users/servers and avoid just spraying the network looking for any host we can get access to.

This script saves time by allowing you to specifically target hosts that you have administrative access to. For example, if you gain access to the "EXAMPLE\JohnDoe" domain account, you can use Invoke-AdminAccessFinder to discover which hosts EXAMPLE\JohnDoe has administrative access on, and use that information to target those hosts rather than just spraying the credentials across the entire network.

Requirements:
----------------
**[PowerView's Invoke-EnumerateLocalAdmin](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon) CSV Output**:

PowerView's Invoke-EnumerateLocalAdmin will query all active machines on a network for it's local administrators. This takes some time but only needs to be done once so doing this ahead of time can be advantageous.

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
