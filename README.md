# PowerHungry
**Twitter: [@DennisMald](https://twitter.com/DennisMald)**

PowerHungry is a repository of experimental PowerShell tools I am developing mainly to hone my PowerShell-Fu.

Current Scripts:
----------------
**Invoke-AdminAccessFinder**: Invoke-AdminAccessFinder is a supplement to PowerView's Invoke-EnumerateLocalAdmin that will search a list of hosts that the specified SamAccountName (user or group) has administrative access to. Invoke-AdminAccessFinder works by importing the CSV output from  PowerView's Invoke-EnumerateLocalAdmin function which should be generated ahead of time Invoke-AdminAccessFinder identifies the SamAccountName specified as well as it's group membership, recursively (with TokenGroups) so that it can search every single group the specified identity is a part of.  Invoke-AdminAccessFinder will return a list of hosts that the identity and any of it's group memberships have administrative access on.

On first execution of Invoke-AdminAccessFinder, it will ask for the CSV file to import. Once imported, Invoke-AdminAccessFinder will not ask for the CSV file again for the duration of the PowerShell session, unless the -Clean switch is specified.

Thanks to  [@harmj0y](https://twitter.com/harmj0y) for the random PowerShell tips and of course for PowerView <https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1>
