# PowerHungry
**Twitter: [@DennisMald](https://twitter.com/DennisMald)**

PowerHungry is a repository of experimental PowerShell tools I am developing mainly to hone my PowerShell-Fu.

Current Scripts:
----------------
**Search-LocalAdmins**: Finds boxes a specified identity has local admin on,  
based on the CSV output from **[PowerView's](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) Invoke-EnumerateLocalAdmin**.

**Get-EffectiveGroups**: Recursively enumerate groups a specific identity is a member of

Example Usage:
----------------
(Read individual scripts for individual usage)

Get computer names that a particular user has admin access to

    PS C:\> Search-LocalAdmins -ImportCSV c:\test\localadmins.csv
    PS C:\> Get-AdUser -Identity "JohnDoe" | Get-EffectiveGroups -Quick | ForEach-Object {$_ | Search-LocalAdmins}
    
Example Usage Explanation:
----------------
* **Search-LocalAdmins -ImportCSV c:\test\localadmins.csv** = Imports the Invoke-EnumerateLocalAdmin CSV into memory for processing  
* **Get-AdUser -Identity "JohnDoe"** = Get JohnDoe's user object from the Active Directory  
* **| Get-EffectiveGroups -Quick** = Get JohnDoe's effective groups (nested groups)  
* **| ForEach-Object {$_ | Search-LocalAdmins}** = Searches all of JohnDoe's effective groups for admin access based on CSV file imported earlier  
    
Note: **Search-LocalAdmins -ImportCSV** only needs to be done once per PowerShell session
