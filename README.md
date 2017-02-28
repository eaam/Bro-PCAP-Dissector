# Bro-PCAP-Dissector
Bro script to dissect PCAP files in a way that facilitates active threat hunting by employing stack counting techniques. The script accepts PCAP fileas an input, scans the existence of major network protocols (i.e. HTTP,DNS,SMB,RDP,SSH,SSL,FTP and IRC) and produce sorted and counted lists of interesting fields/headers upon the existence of any of the previous protocols.

Running the script using this command "bro -C -r trace.pcap dissector.bro" produces the following samples (different PCAPs) output


==========================================================
Bytes Downloaded > {3000000 Bytes / 3 MB}
==========================================================
Format: size (Descending), client IP, server IP, server port
CTF/maccdc2012_00001.pcap

	5366941               192.168.203.64   <-------  192.168.202.68   : 55554/tcp
	5184633               192.168.204.70   <-------  192.168.202.68   : 55554/tcp
	4203410               192.168.204.45   <-------  192.168.202.68   : 55554/tcp
	4091323               192.168.27.100   <-------  192.168.202.110  : 4444/tcp
	4086085               192.168.28.100   <-------  192.168.203.45   : 54321/tcp
	3497984               192.168.27.100   <-------  192.168.203.45   : 9898/tcp
	3497812               192.168.24.100   <-------  192.168.203.45   : 54322/tcp
	3496305               192.168.26.100   <-------  192.168.203.45   : 54344/tcp
	3476280               192.168.24.100   <-------  192.168.202.110  : 4444/tcp

 
==========================================================
Bytes Uploaded > {1000000 Bytes / 1 MB}
==========================================================
Format: size (Descending), client IP, server IP, server port
ismellpackets/Hidden.pcap

	1510081441            192.168.4.5      -------> 207.171.185.200  : 443/tcp
	1436668500            192.168.4.5      -------> 74.125.239.3     : 443/tcp
	1429743201            192.168.4.5      -------> 207.171.187.117  : 443/tcp
	1068033242            192.168.4.5      -------> 23.212.8.120     : 80/tcp
	742832115             192.168.4.5      -------> 207.171.187.117  : 443/tcp
	729590415             192.168.4.5      -------> 207.171.187.117  : 443/tcp
	251404609             192.168.4.5      -------> 23.67.247.112    : 80/tcp
	8393910               192.168.4.5      -------> 207.171.187.117  : 443/tcp
 


==========================================================
Conn Duration > {600 Second / 10 Minutes}
==========================================================
Format: session duration in seconds (Descending) , client IP, server IP, server port
CTF/maccdc2012_00001.pcap

	1840                  192.168.202.68   <------->     192.168.28.203   : 22/tcp
	1788                  192.168.202.109  <------->     192.168.22.254   : 22/tcp
	1765                  192.168.204.70   <------->     192.168.202.68   : 55554/tcp
	1752                  192.168.202.109  <------->     192.168.23.254   : 22/tcp
	1680                  192.168.28.100   <------->     192.168.203.45   : 54321/tcp
	1650                  192.168.202.109  <------->     192.168.24.254   : 22/tcp
	1645                  192.168.28.100   <------->     192.168.204.45   : 1025/tcp
	1632                  192.168.28.100   <------->     192.168.202.112  : 1025/tcp
	1623                  192.168.202.109  <------->     192.168.25.254   : 22/tcp
	1567                  192.168.202.109  <------->     192.168.27.254   : 22/tcp
	1533                  192.168.202.109  <------->     192.168.28.254   : 22/tcp
	1522                  192.168.24.100   <------->     192.168.202.90   : 4499/tcp
	1470                  192.168.24.100   <------->     192.168.202.90   : 4499/tcp
	1445                  192.168.202.109  <------->     192.168.21.254   : 22/tcp
	1435                  192.168.24.100   <------->     192.168.203.45   : 1025/tcp

 
==========================================================
Conn Listening_TCP_Ports_on_Private_IPs
==========================================================
Format: # of sessions (Ascending), tcp port, server IP, protocol
CTF/maccdc2012_00003.pcap

	1             8089/tcp  listening on  192.168.22.253   ssl
	1             8000/tcp  listening on  192.168.25.253   http
	1             5432/tcp  listening on  192.168.203.45   -
	1             139/tcp   listening on  192.168.25.102   ntlm,gssapi,smb,dce_rpc
	1             22/tcp    listening on  192.168.28.203   ssh
	1             22/tcp    listening on  192.168.21.254   ssh
	1             445/tcp   listening on  192.168.27.100   ntlm,smb,dce_rpc
	1             80/tcp    listening on  192.168.22.253   http
	1             445/tcp   listening on  192.168.25.102   ntlm,gssapi,smb,dce_rpc
	1             80/tcp    listening on  192.168.21.202   http
	1             443/tcp   listening on  192.168.201.2    ssl
	1             8080/tcp  listening on  192.168.23.203   http
	1             80/tcp    listening on  192.168.28.101   http
	2             55553/tcp listening on  192.168.202.68   ssl
	2             80/tcp    listening on  192.168.23.101   http
	2             80/tcp    listening on  192.168.25.202   http
	3             22/tcp    listening on  192.168.23.101   ssh
	4             445/tcp   listening on  192.168.27.100   ntlm,smb
	4             80/tcp    listening on  192.168.25.102   http
	5             443/tcp   listening on  192.168.25.253   ssl
	5             443/tcp   listening on  192.168.22.253   ssl
	7             443/tcp   listening on  192.168.22.254   ssl
	13            80/tcp    listening on  192.168.202.78   http
	17            443/tcp   listening on  192.168.25.254   ssl
	18            22/tcp    listening on  192.168.22.253   ssh


 
==========================================================
Conn Listening_TCP_Ports_on_Public_IPs
==========================================================
Format: # of sessions (Ascending), tcp port, protocol 
2015-06-30-traffic-analysis-exercise.pcap

	1             6998/tcp  -------> -
	3             80/tcp    -------> http
	9             443/tcp   -------> ssl


 

==========================================================
HTTP Odd_Hosts
==========================================================
Format: # of occurence (Ascending), odd HTTP hosts

	1             whos.amung.us
	1             widgets.amung.us
	1             a.topgunn.photography
	1             magusserver.top
	1             ckea.ca
	2             g00.co
	2             x.ss2.us
	2             www.postagens.net
	3             mohecy.tk
	4             185.82.202.170
	6             ululataque-forstbea.bondcroftatvs.co.uk
	7             e7qx9y.he6gnm.top
	15            www.emidioleite.com.br
	23            5.34.183.40


==========================================================
HTTP Odd_URIs
==========================================================
Format: # of occurence (Ascending), odd URIs (20 chars before and after the matched pattern)

	1             an =    Iniciar{133}  Downlaod                                         x.x.x.x       ------->  www.devyatinskiy.ru
	1             )|utmcmd=organic|                                                      x.x.x.x       ------->  www.google-analytics.com
	1             an =    Iniciar{69}                                                    x.x.x.x       ------->  www.devyatinskiy.ru
	1             ta Pasta === C:\Users\Matthew.F                                        x.x.x.x       ------->  www.devyatinskiy.ru
	1             =    Continuou ... extrair                                             x.x.x.x       ------->  www.devyatinskiy.ru
	1             ks /create /tn "SYSFROGGYPC37"                                         x.x.x.x       ------->  api.devyatinskiy.ru
	1             in A. Abbott | Lit2Go ETC&utm                                          x.x.x.x       ------->  www.google-analytics.com
	1             " /F                                                                   x.x.x.x       ------->  api.devyatinskiy.ru
	1             =render_toolbox|5196&cmenu=null                                        x.x.x.x       ------->  m.addthis.com   
	1             jpd2buu.3sx.vbs" /sc onlogon /R                                        x.x.x.x       ------->  api.devyatinskiy.ru
	1             n =     Iniciar{121} - Download                                        x.x.x.x       ------->  www.devyatinskiy.ru
	1             an =    Iniciar{90}                                                    x.x.x.x       ------->  www.devyatinskiy.ru
	1             40/bibi/dll.dll|P5PKLOY+IYtRWfZ                                        x.x.x.x       ------->  www.devyatinskiy.ru
	1             n|4530|817,sh|4534|5,sh|4537|                                          x.x.x.x       ------->  m.addthis.com   
	1             0,700,400italic|Josefin+Slab:40                                        x.x.x.x       ------->  fonts.googleapis.com
	1             t[1329]                                                                x.x.x.x       ------->  api.devyatinskiy.ru
	1             index.php?N=a37[7]FROGGY-PC-Mat                                        x.x.x.x       ------->  api.devyatinskiy.ru
	1             /tr "C:\Windows\SysWOW64\Java\m                                        x.x.x.x       ------->  api.devyatinskiy.ru
	1             240/bibi/W7.zip|38|http://65.18                                        x.x.x.x       ------->  www.devyatinskiy.ru
	1                Pasta === C:\Users\Matthew.F                                        x.x.x.x       ------->  www.devyatinskiy.ru
	2             [?] Operating syst                                                     x.x.x.x       ------->  www.devyatinskiy.ru
	2               |  _|\x0d                                                            x.x.x.x       ------->  www.devyatinskiy.ru
	2             \Ionic.Zip.Reduc                                                       x.x.x.x       ------->  www.devyatinskiy.ru
	2               |_  |\x0d                                                            x.x.x.x       ------->  www.devyatinskiy.ru
	2             [!] No valid threa                                                     x.x.x.x       ------->  www.devyatinskiy.ru
	2             hLogonW handles..\x0d                                                  x.x.x.x       ------->  www.devyatinskiy.ru
	2             \x09|     |_  |_| |_| . |___| | |_                                     x.x.x.x       ------->  www.devyatinskiy.ru
	2             \x09|  V  |  _|_  | |  _|___|   |_                                     x.x.x.x       ------->  www.devyatinskiy.ru
	2             rogman\AppData\Local\Temp\Java                                         x.x.x.x       ------->  www.devyatinskiy.ru

==========================================================
HTTP Referrers
==========================================================
Format: # of occurence (Ascending), TLD part of HTTP referrer

	1             www.google.com.au
	2             uacltr.securetopc.top
	15            3wzn5p2yiumh7akj.waytopaytosystem.com
	27            -
	51            www.outdoorsamoa.com
	54            au.search.yahoo.com
	56            www.koeppl.com
	86            planetside.co.uk

 
==========================================================
HTTP User-Agents
==========================================================
Format: # of occuernce (Ascending), HTTP user-agent

	1             -
	1             Microsoft NCSI
	2             Microsoft-CryptoAPI/6.1
	243           Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko


==========================================================
HTTP Methods
==========================================================
Format: # of occurence (Ascending), HTTP request method 
 
	9             POST
	274           GET

==========================================================
HTTP Response_Codes
==========================================================
Format: # of occurence (Ascending), HTTP response status code 

	1             307
	2             403
	6             404
	6             204
	6             301
	44            302
	232           200
 
==========================================================
HTTP Client_Requests
==========================================================
 Format: # of HTTP requests (Ascending), client IP
 
	63            x.x.x.x
	136           x.x.x.x
	198           x.x.x.x

==========================================================
DNS NXDOMAIN_Queries
==========================================================
Format: # of queries to NX domains (Ascending), client IP

	2             x.x.x.x
	3             x.x.x.x
	21            x.x.x.x
 
 ==========================================================
DNS Client_Queries
==========================================================
Format: # of DNS queries (Ascending), client IP

	23            192.168.122.52
	32            192.168.122.130
	32            192.168.122.132
 
==========================================================
DNS Query_Types
==========================================================
Format: # of occurence (Ascending), DNS query type

	1             TXT
	2             AAAA
	4             PTR
	7             *
	99            A 
 
==========================================================
DNS Odd_Queries
==========================================================
Format: # of occurence (Ascending), odd DNS query

	1             zt.1rx.io
	1             sync.1rx.io
	1             ccjlwb22w6c22p2k.onion.to
	1             bapanivato.abjibapanichhatedi.org
	1             cm.g.doubleclick.net
	1             x.bidswitch.net
	1             ubb67.3c147o.u806a4.w07d919.o5f.f1.b80w.r0faf9.e8mfzdgrf7g0.groupprograms.in
	1             runlove.us
	1             r03afd2.c3008e.xc07r.b0f.a39.h7f0fa5eu.vb8fbl.e8mfzdgrf7g0.groupprograms.in
	1             kritischerkonsum.uni-koeln.de
	1             7oqnsnzwwnm6zb7y.gigapaysun.com
	1             ip-addr.es
	1             va872g.g90e1h.b8.642b63u.j985a2.v33e.37.pa269cc.e8mfzdgrf7g0.groupprograms.in
	1             i.w55c.net
	1             wme0hsxg.e6to8jdmiysycbmeepm29nfprvigdwev.top
	1             ffoqr3ug7m726zou.le2brr.bid
	1             bid.g.doubleclick.net
	1             um.simpli.fi
	2             googleads.g.doubleclick.net
	2             connexity.net
	2             px.owneriq.net
	1             stats.g.doubleclick.net
	1             7c416cff040b7449328d095b3e98e12d5f12a207.googledrive.com
	1             cl.ly
	1             connect.facebook.net 
	2             api.devyatinskiy.ru 

==========================================================
SMB2 Sessions
==========================================================
Format: # of sessions (Ascending), client IP, server IP, server port

 	494           x.x.x.x    -------> x.x.x.x     :  445/tcp
	532           x.x.x.x    -------> x.x.x.x     :  445/tcp
 
==========================================================
SMB2 Usernames
==========================================================
Format: # of occurence (Ascending), domain\username

	21            Domain            \          Username1
	494           Domain            \          Username2
 
==========================================================
SMB2 Hostnames
==========================================================
Format: # of occurence (Ascending), SMB hostname

 	21            ServerABC
	494           ServerXYZ
 
==========================================================
SMB2 File_Actions
==========================================================
Format: # of occurence (Ascending), file action

	2             SMB::FILE_WRITE
	52            SMB::FILE_READ
	188           SMB::FILE_CLOSE
	252           SMB::FILE_OPEN
 
==========================================================
SMB2 File_Names
==========================================================
Format: # of occurence (Ascending), SMB file name

	1             ui\SwDRM.dll
	1             desktop.ini
	1             inetpub\wwwroot\iis-85.png:Zone.Identifier
	4             inetpub\history\CFGHISTORY_0000000004
	4             inetpub\temp
	4             inetpub\logs\LogFiles\W3SVC1
	4             inetpub\history\CFGHISTORY_0000000002
	4             inetpub\logs\LogFiles
	4             inetpub\history
	4             inetpub\custerr\en-US
	4             inetpub\custerr
	4             inetpub\temp\appPools
	4             inetpub\history\CFGHISTORY_0000000003
	4             inetpub\temp\IIS Temporary Compressed Files\DefaultAppPool
	4             Thumbs.db:encryptable
	4             inetpub\temp\IIS Temporary Compressed Files
	4             inetpub\logs
	4             temp
	4             inetpub\wwwroot\Thumbs.db:encryptable
	4             inetpub\history\CFGHISTORY_0000000001
	4             inetpub\temp\appPools\DefaultAppPool
	5             Users\desktop.ini
	5             Program Files\desktop.ini
 
==========================================================
SSH Sessions
==========================================================
Format: # of occurence (Ascending), client ip, server ip, server port

	6             x.x.x.x    -------> y.y.y.y    : 22/tcp
	2             x.x.x.x    -------> y.y.y.y    : 2222/tcp	
==========================================================
SSH Client_Strings
==========================================================
Format: # of occurence (Ascending), SSH client string

	6             SSH-2.0-PUTTY
 
 
 
==========================================================
SSH Server_Strings
==========================================================
Format: # of occurence (Ascending), SSH server string

	6             SSH-2.0-OpenSSH_7.1p2 Debian-1

 
==========================================================
SSH Auth_Success
==========================================================
Format: # of occurence (Ascending), SSH auth_success result (True/False)

	5             F
	7             T

==========================================================
SSL Servers_Names
==========================================================
Format: # of occurence (Ascending), SSL server name

	1             nexusrules.officeapps.live.com
	1             licensing.mp.microsoft.com
	1             sqm.telemetry.microsoft.com
	1             iecvlist.microsoft.com
	1             nexus.officeapps.live.com
	2             v10.vortex-win.data.microsoft.com
	4             f5xraa2y2ybtrefz.tor2web.org
 
==========================================================
SSL Issuers
==========================================================
Format: # of occurence (Ascending), SSL issuer
 
	1             emailAddress=sampo@iki.fi,CN=brutus.neuronio.pt,OU=Desenvolvimento,O=Neuronio\, Lda.,L=Lisboa,ST=Queensland,C=PT
	2             CN=4Tw88SdvHNKgZH3boHtKG4HL,O=Q31367JVj8IhD4FmHMwKPhUV,L=PVji8090PTSZMEYq0XlXrYzn,ST=ST,C=CN
	8             CN=Verizon Akamai SureServer CA G14-SHA2,OU=Cybertrust,O=Verizon Enterprise Solutions,L=Amsterdam,C=NL
	14            CN=COMODO RSA Domain Validation Secure Server CA,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
	18            CN=457jPxEfw8rSShbih3y7p6D3,O=E3LrXvD3rrL8AjBQ9HpYhfAK,L=MdoCgaSQxzrPq5p367Y1Ksjo,ST=ST,C=CN
	33            CN=Microsoft IT SSL SHA2,OU=Microsoft IT,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US
	56            CN=Google Internet Authority G2,O=Google Inc,C=US 



==========================================================
SSL Validation_Status
==========================================================
Format: # of occurence (Ascending), SSL cert validation result

	15            ok
	16            self signed certificate
 
 
==========================================================
RDP Sessions
==========================================================
Format: # of sessions (Ascending), client IP, server IP, server port 

	2             x.x.x.x    -------> y.y.y.y     : 3389/tcp
	5             x.x.x.x    -------> y.y.y.y     : 3389/tcp
	15            x.x.x.x    -------> y.y.y.y     : 3389/tcp

==========================================================
RDP Usernames
==========================================================
Format: # of occurence (Ascending), domain \ username

	2             Domain\Username
	20            Domain\Username


==========================================================
IRC session
==========================================================
Format: # of occurence (Ascending), client IP, server IP, server port

	3             10.240.0.3       -------> 10.240.0.2       : 31337/tcp
	3             10.240.0.4       -------> 10.240.0.2       : 31337/tcp
	3             10.240.0.5       -------> 10.240.0.2       : 31337/tcp


==========================================================
IRC username
==========================================================
Format: # of occurence (Ascending), IRC username

	9             root-poppopret
 

==========================================================
IRC nick
==========================================================
Format: # of occurence (Ascending), IRC nickname

	3             Matir
	3             andrewg
	3             itsl0wk3y

 
==========================================================
FTP Sessions
==========================================================
Format: # of occurence (Ascending), client IP, Server IP, server port

	4             x.x.x.x    -------> y.y.y.y    : 21/tcp

==========================================================
FTP Usernames
==========================================================
Format: # of occurence (Ascending), FTP username

	4             admin

==========================================================
FTP Passwords
==========================================================
Format: # of occurence (Ascending), FTP passwords

	4             <hidden>
 
==========================================================
FTP Current_Working_Directories
==========================================================
Format: # of occurence (Ascending), FTP Current Working Directory

	1             /home
	3             .

==========================================================
FTP Commands
==========================================================
Format: # of occurence (Ascending), FTP command

	4             PORT

==========================================================
File MIME_Types
==========================================================
Format: # of occurence (Ascending), mime type, communication protocol

	1             application/x-dosexec                    -------> FTP_DATA
	1             image/x-icon                             -------> HTTP
	2             application/x-shockwave-flash            -------> HTTP
	6             text/html                                -------> HTTP
	9             application/x-dosexec                    -------> HTTP
	10            text/plain                               -------> HTTP
	13            image/png                                -------> HTTP


