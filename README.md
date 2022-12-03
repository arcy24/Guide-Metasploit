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
