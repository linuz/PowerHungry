Get-AllTrusts
----------------
Get-AllTrusts will list the trusts for the inputted or current domain/forest. Will also output status of SIDFiltering and SelectiveAuthorization

If SIDFiltering is disabled, attackers can perform a SIDHistory attack to gain DA/EA privilleges from one Domain/Forest to another Domain/Forest. See more on the attack here:
https://adsecurity.org/?p=1640

Usage:
----------------
Will grab the trust information for the domain the current user is a member of

    PS C:\> Get-AllTrusts
                

Will grab the trust information for all the trusts with ABC.LOCAL Domain/Forest. You can pipe the results to Format-Table (ft) for easier reading

    PS C:\> Get-AllTrusts -domain ABC.LOCAL | ft

