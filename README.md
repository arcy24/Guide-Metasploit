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

