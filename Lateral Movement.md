## General
* [Powercat](#powercat)
* [Add  user to local admin or domain group](#Add-user-to-local-admin-or-domain-group)
* [Execute commands on a machine remotely](#Execute-commands-on-a-machine-remotely)
* [Powercat](#powercat)
* [Powercat](#powercat)
* [Powercat](#powercat)
* [Powercat](#powercat)
* [Powercat](#powercat)
* [Powercat](#powercat)
* [Powercat](#powercat)
* [Powercat](#powercat)
* [Powercat](#powercat)
* [Powercat](#powercat)
* [Powercat](#powercat)
* 
# Powercat
```
-l Listen for a connection. [Switch]
\
-c Connect to a listener. [String]\
-p The port to connect to, or listen on. [String]\
-e Execute. (GAPING_SECURITY_HOLE) [String]\
-ep Execute Powershell. [Switch]\
-r Relay. Format: "-r tcp:10.1.1.1:443" [String]\
-u Transfer data over UDP. [Switch]\
-dns Transfer data over dns (dnscat2). [String]\
-dnsft DNS Failure Threshold. [int32]\
-t Timeout option. Default: 60 [int32]\
-i Input: Filepath (string), byte array, or string. [object]\
-o Console Output Type: "Host", "Bytes", or "String" [String]\
-of Output File Path. [String]\
-d Disconnect after connecting. [Switch]\
-rep Repeater. Restart after disconnecting. [Switch]\
-g Generate Payload. [Switch]\
-ge Generate Encoded Payload. [Switch]\
-h Print the help message. [Switch]\
powercat -l -v -p 443 -t 100
```
# Add user to local admin or domain group
```
net localgroup Administrators <DOMAIN>\<USER> /add
```
```
Add-DomainGroupMember -Identity "PRODUCTIONMANAGERS" -Members usfun\pastudent131
```
# Execute commands on a machine remotely
