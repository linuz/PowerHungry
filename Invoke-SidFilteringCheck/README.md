Invoke-SidFilteringCheck
----------------
Invoke-SidFilteringCheck will list the trusts for the inputted or current Domain/Forest and will output whether SIDFiltering is enabled or disabled on that trust. 
 
If SIDFiltering is disabled, attackers can perform a SIDHistory attack to gain DA/EA privilleges from one Domain/Forest to another Domain/Forest. See more on the attack here:
https://adsecurity.org/?p=1640

SIDFiltering Trust Status information for reference:

    Forest Trust - if SIDFilteringForestAware is True, SIDFiltering is disabled on the forest trust
    External Trust - if SIDFilteringQuarantined is False, SIDFiltering is disabled on the external trust

Usage:
----------------
Will grab the trust information for the domain the current user is a member of

    PS C:\> Invoke-SidFilteringCheck
                

Will grab the trust information for all the trusts with ABC.LOCAL Domain/Forest. You can pipe the results to Format-Table (ft) for easier reading

    PS C:\> Invoke-SidFilteringCheck ABC.LOCAL | ft

