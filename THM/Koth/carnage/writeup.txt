1) start burpsuite
2) goto carnage.thm:82/index.php
3) intercept the package
4) upload a php-revere-shell with .gif format and on burp add .php on the gif
5) make a listner
6) goto carnage:82/images and open ur exploit
	check if you can get to /root
7) privilage
8) [PassProtect]
9) close port 82
	sudo lsof -t -i tcp:80 | sudo xargs killexit
10) Be king ; get flag	
