# Enumeration
* [Domain](#Domain)
* [Computers](#Computers)
* [Users](#Users) 
* [Shares](#Shares)
* [Groups](#Groups)
* [Domain Trusts](#Domain-Trusts)
* [Forest trust](#Forest-trust)
* [Organizational Unit (OU)](#Organizational-Unit-OU)
* [Group Policy](#Group-Policy)

## Domain
\
**Get Current Domain**
~~~
Get-NetDomain // PowerView.ps1

Get-ADDomain // ADModule
~~~
\
**Get Object of another Domain**
~~~
Get-NetDomain -Domain <target-domain>

Get ADDomain -Identity <target-domain>
~~~
\
**Get all domains in current forest**
~~~
Get-ForestDomain
~~~
\
**Get Domain SID for the current Domain**
~~~
Get-DomainSID

(Get-ADDomain).DomainSID

The SID (Security IDentifier)
is a unique ID number that a computer or domain controller uses to identify you.
It is a string of alphanumeric characters assigned to each user on a Windows computer, or to each user, group, 
and computer on a domain-controlled network such as Indiana University's Active Directory
~~~
\
**Get domain/forest trusts**
~~~
Get-DomainTrust
Get-ForestTrust
~~~
\
**Domain Policy** 
~~~
Get Domain Policy for the current Domain

Get-DomainPolicy

(Get-DomainPolicy)."system access"
(Get-DomainPolicy)."kerberos Policy"
~~~
\
**Get Domain Policy for another Domain**
~~~
(Get-DomainPolicy -domain <target-domain>)."system access" // ADModule
~~~

## Computers
~~~
Get a list of computers in the current Domain
Get-NetComputer
Get-NetComputer -OperatingSystem "*Server 2016*"
Get-NetComputer -Ping
Get-NetComputer -FullData

Get-ADComputer -Filter *
Get-ADComputer -Filter * | select Name
Get-ADComputer -Filter 'OperatingSystem -like "*Server 2016*"' -Properties Operating System | select Name,OperatingSystem
Get-ADComputer -Filter * -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $_DNSHostName}
Get-ADComputer -Filter * -Properties *
~~~

## Users
~~~
Get list of all properties for users in the current Domain
Get-UserProperty
Get-UserProperty -Properties pwdlastset
Get-UserProperty -Properties logoncount     // Small logon account is not actively used or it is a decoy account 
Get-UserProperty -Properties badpwdcount    // These properties can be used to identify a honeyuser/decoy user from a legit one 

Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -MemberType *Property | select Name
Get-ADUser -Filter * -Properties * | select name,@{expression={[datetime]::fromFileTime($_.pwdlastset}}
~~~
\
**Search for particular string in a user’s attributes (Description)**
~~~
Find-UserField -SearchField Description -SearchTerm "built"

Get-ADUser -Filter 'Description -like "*built*"' -Properties Description | select name, Description
~~~
\
**Get list of users in the current Domain**
~~~
Get-NetUser
Get-NetUser | select cn
Get-NetUser -Username <username>

Get-ADUser -Filter * -Properties *
Get-ADUser -Filter * -Properties * | select Name 
Get-ADUser -Identity <username>
Get-ADUser -Identity <username> -Properties *
~~~
\
**Get actively logged on users on a computer**
~~~
// needs local admin rights on target
Get-NetLoggedon -ComputerName <computer-name>
~~~
\
**Get locally logged on users on a computer**
~~~
// needs remote registry on target/local admin rights
Get-LoggedonLocal -ComputerName <computer-name>
~~~
\
**Get last logged on users on a computer**
~~~
// needs admin rights and remote registry on target 
Get-LastLoggedOn -ComputerName <computer-name>
~~~

## Shares
~~~
Find shares on hosts in current Domain
Invoke-ShareFinder -Verbose
Invoke-ShareFinder -Verbose -ExcludeStandard -ExcludePrint -Exclude IPC

 Find interesting shares in the domain, ignore default shares, and check access
Find-DomainShare -ExcludeStandard -ExcludePrint -ExcludeIPC -CheckShareAccess
~~~
\
**Get all fileservers of the Domain**
~~~
Get-NetFileServer -Verbose   // Looks for high value targets - where lots of users connect/authenticate
~~~
\
**Find sensitive files on computers in the Domain**
~~~
Invoke-FileFinder -Verbose  // Need read/write privs on a share
~~~

## Groups
~~~
Get all groups containing the word ‘admin’ in the Group name
Get-NetGroup
Get-NetGroup -GroupName *admin*
Get-NetGroup -GroupName *admin* -Domain <target-domain>
Get-NetGroup -FullData
Get-NetGroup "admin"
Get-NetGroup 'Domain Admins'
Get-NetGroup 'Domain Admins' -FullData

Get-ADGroup -Filter *
Get-ADGroup -Filter * | select name
Get-ADGroup -Filter 'Name -like "*admin*"' | select Name
~~~
\
**Get all members of the Domain Admin’s or Administrator Group**

~~~
Get-NetGroupMember -GroupName 'Domain Admins'
Get-NetGroupMember -GroupName 'Enterprise Admins' -Domain <domain>
Get-NetGroupMember -GroupName 'Domain Admins' -Recurse
Get-NetGRoupMember -GroupName 'Administrators' -Recurse 
Get users inside "Administrators" group. If there are groups inside of this group, the -Recurse option will print the users inside the others groups also
Enterprise Admins group only exists in the rootdomain of the forest
>> IsGroup:False this mean its user
>> IsGroup:True This mean its Group 
Get-ADGroupMember -Identity 'Domain Admins' -Recursive
>> Find members of the DA group
Get-DomainGroupMember "Domain Admins" | select -ExpandProperty membername
~~~
\
**Get all Group Memberships for a user**
~~~
Get-NetGroup -UserName "<username>"

Get-ADPrincipalGroupMembership -Identity <username>
~~~
\
**Get all the groups in the current Domain**
~~~
Get-NetGroup
Get-NetGroup -Domain <target-domain>
Get-NetGroup -FullData

Get-ADGroup -Filter * | select Name
Get-ADGroup -Filter * -Properties *
~~~
\
**Get information for the Domain Admins group**
~~~
Get-DomainGroup "Domain Admins"
~~~
\
**Get members of all the Local Groups on a machine**
~~~
// needs admin privs 
Get-NetLocalGroup -ComputerName <computer> -Recurse
~~~
\
**List all the Local Groups on a machine**
~~~
Get-NetLocalGroup -ComputerName <computer-name>   
Get-NetLocalGroup -ComputerName <computer-name> -ListGroups
you need admin rights in no DC hosts
*if we remove -ListGroups this will be mean show what administrator in which groups
#Get users of localgroups in computer
~~~
## Domain Trusts

**Domain Trust mapping**
~~~
Get-DomainTrustMapping
~~~
\
 **Get a list of all domain trusts for the current domain**
~~~
Get-NetDomainTrust
Get-NetDomainTrust –Domain (xxxx.test1.test.local)
Get-ADTrust
Get-ADTrust –Identity (<xxxx.test1.test.local)
~~~

## Forest trust

 **Get details about the current forest**
~~~
Get-NetForest
Get-NetForest –Forest eurocorp.local
Get-ADForest
Get-ADForest –Identity eurocorp.local
~~~
\
**Get all domains in the current forest**
~~~
Get-NetForestDomain
Get-NetForestDomain –Forest eurocorp.local
(Get-ADForest).Domains
~~~

## Organizational Unit OU

**Get OUs in a domain**
~~~
Get-NetOU -FullData
Get-DomainOU -FullData
Get-ADOrganizationalUnit -Filter * -Properties *
~~~

**Get GPO applied on an OU. Read GPOname from gplink attribute from**
~~~
Get-NetOU
Get-NetGPO -GPOname "{AB306569-220D-43FF-B03B83E8F4EF8081}"
Get-GPO -Guid AB306569-220D-43FF-B03B-83E8F4EF8081
(GroupPolicy module)
~~~
\
**Get GPOs applied to a specific OU**
~~~
Get-DomainOU *WS* | select gplink
Get-DomainGPO -Name "{3E04167E-C2B6-4A9A-8FB7-C811158DC97C}"
~~~
\
**o list all the computers in the StudentsMachines OU**
~~~
Get-NetOU StudentMachines | %{Get-NetComputer -ADSPath $_}
~~~
\
**Get computers in an OU**
~~~
 %{} is a looping statement
Get-DomainOU -name Servers | %{ Get-DomainComputer -SearchBase $_.distinguishedname } | select dnshostname
~~~

## Group Policy
\
**Get list of GPO in current domain**
~~~
Get-NetGPO | select displayname
Get-NetGPO
Get-NetGPO -ComputerName dcorpstudent1.dollarcorp.moneycorp.local
Get-GPO -All (GroupPolicy module)
Get-GPResultantSetOfPolicy -ReportType Html -Path C:\Users\Administrator\report.html (Provides RSoP)
~~~
\
**Get GPO(s) which use Restricted Groups or groups.xml for interesting users**
~~~
Get-NetGPOGroup
~~~
\
***Restricted Groups***
~~~
Restricted Groups allows the administrator to configure local groups on client computer. For example, you could add a helpdesk support group to all clients on your desktop. This video looks at how to configure local groups on your client computer using Group Policy rather than visiting each computer to make the changes.
~~~
\
 **Get Restricted Groups set via GPOs, look for interesting group memberships forced via domain**
 ~~~
Get-DomainGPOLocalGroup -ResolveMembersToSIDs | select GPODisplayName, GroupName, GroupMemberOf, GroupMembers
~~~
\
**Get users which are in a local group of a machine using GPO**
~~~
Find-GPOComputerAdmin –Computername dcorpstudent1.dollarcorp.moneycorp.local
~~~
\
**Get machines where the given user is member of a specific group**
~~~
Find-GPOLocation -UserName student1 -Verbose
~~~
\
 **Enumerate what machines that a particular user/group identity has local admin rights to**
 ~~~
Get-DomainGPOUserLocalGroupMapping -Identity
~~~
**enumerate what machines that a given user in the specified domain has RDP access rights to**
~~~
Get-DomainGPOUserLocalGroupMapping -Identity  -Domain  -LocalGroup RDP
~~~
