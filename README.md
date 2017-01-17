# Bro-PCAP-Dissector
Bro script to dissect PCAP files in a way that facilitates active threat hunting by employing stack counting techniques. The script accepts PCAP fileas an input, scans the existence of major network protocols (i.e. HTTP,DNS,SMB,RDP,SSH,SSL,FTP and IRC) and produce sorted and counted lists of interesting fields/headers upon the existence of any of the previous protocols.

Running the script using this command "bro -C -r trace.pcap pcap-dissector.bro" produces the following samples output


==========================================================
Bytes Downloaded > {1000000 Bytes / 1 MB}
==========================================================
 
    5243355          x.x.x.x   <-------  x.x.x.x  : 80/tcp
    2867458          x.x.x.x   <-------  x.x.x.x  : 443/tcp
    1136345          x.x.x.x   <-------  x.x.x.x  : 443/tcp
    1070806          x.x.x.x   <-------  x.x.x.x  : 443/tcp
    1029117          x.x.x.x   <-------  x.x.x.x  : 80/tcp
 
==========================================================
Bytes Uploaded > {1000000 Bytes / 1 MB}
==========================================================
 
	2231614               x.x.x.x      -------> x.x.x.x  : 1521/tcp
	2018871               x.x.x.x      -------> x.x.x.x  : 524/tcp
	1734451               x.x.x.x      -------> x.x.x.x  : 22/tcp
	1705043               x.x.x.x      -------> x.x.x.x  : 22/tcp
	1306928               x.x.x.x      -------> x.x.x.x  : 993/tcp
	1299905               x.x.x.x      -------> x.x.x.x  : 25/tcp


==========================================================
Conn Duration > {300 Second / 5 Minutes}
==========================================================
 
	631                   x.x.x.x   <------->     x.x.x.x   : 443/tcp
	506                   x.x.x.x   <------->     x.x.x.x   : 443/tcp
	492                   x.x.x.x   <------->     x.x.x.x   : 443/tcp
	333                   x.x.x.x   <------->     x.x.x.x   : 443/tcp
	329                   x.x.x.x   <------->     x.x.x.x   : 80/tcp  
 
 
==========================================================
Conn Listening_TCP_Ports_on_Private_IPs
==========================================================
 
	1             80/tcp    listening on  x.x.x.x         http
 
 
 
==========================================================
Conn Listening_TCP_Ports_on_Public_IPs
==========================================================
 
	2             443/tcp   -------> -
	5             443/tcp   -------> ssl
	11            80/tcp    -------> http
 

==========================================================
HTTP Odd_Hosts
==========================================================

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
 
	1             -
	1             Microsoft NCSI
	2             Microsoft-CryptoAPI/6.1
	243           Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko


==========================================================
HTTP Methods
==========================================================
 
	9             POST
	274           GET

==========================================================
HTTP Response_Codes
==========================================================

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
 
	63            x.x.x.x
	136           x.x.x.x
	198           x.x.x.x

==========================================================
DNS NXDOMAIN_Queries
==========================================================
 
	2             x.x.x.x
	3             x.x.x.x
	21            x.x.x.x
 
 ==========================================================
DNS Client_Queries
==========================================================
 
	23            192.168.122.52
	32            192.168.122.130
	32            192.168.122.132
 
==========================================================
DNS Query_Types
==========================================================
 
	1             TXT
	2             AAAA
	4             PTR
	7             *
	99            A 
 
==========================================================
DNS Odd_Queries
==========================================================
 
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

 	494           x.x.x.x    -------> x.x.x.x     :  445/tcp
	532           x.x.x.x    -------> x.x.x.x     :  445/tcp
 
==========================================================
SMB2 Usernames
==========================================================
 
	21            Domain            \          Username1
	494           Domain            \          Username2
 
==========================================================
SMB2 Hostnames
==========================================================
 
 	21            ServerABC
	494           ServerXYZ
 
==========================================================
SMB2 File_Actions
==========================================================
 
	2             SMB::FILE_WRITE
	52            SMB::FILE_READ
	188           SMB::FILE_CLOSE
	252           SMB::FILE_OPEN
 
==========================================================
SMB2 File_Names
==========================================================
 
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
 
	6             x.x.x.x    -------> y.y.y.y    : 22/tcp
	2             x.x.x.x    -------> y.y.y.y    : 2222/tcp	
==========================================================
SSH Client_Strings
==========================================================
 
	6             SSH-2.0-PUTTY
 
 
 
==========================================================
SSH Server_Strings
==========================================================
 
	6             SSH-2.0-OpenSSH_7.1p2 Debian-1

 
==========================================================
SSH Auth_Success
==========================================================
 
	5             F
	7             T

==========================================================
SSL Servers_Names
==========================================================
 
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
 
	1             emailAddress=sampo@iki.fi,CN=brutus.neuronio.pt,OU=Desenvolvimento,O=Neuronio\, Lda.,L=Lisboa,ST=Queensland,C=PT
	2             CN=4Tw88SdvHNKgZH3boHtKG4HL,O=Q31367JVj8IhD4FmHMwKPhUV,L=PVji8090PTSZMEYq0XlXrYzn,ST=ST,C=CN
	8             CN=Verizon Akamai SureServer CA G14-SHA2,OU=Cybertrust,O=Verizon Enterprise Solutions,L=Amsterdam,C=NL
	14            CN=COMODO RSA Domain Validation Secure Server CA,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
	18            CN=457jPxEfw8rSShbih3y7p6D3,O=E3LrXvD3rrL8AjBQ9HpYhfAK,L=MdoCgaSQxzrPq5p367Y1Ksjo,ST=ST,C=CN
	33            CN=Microsoft IT SSL SHA2,OU=Microsoft IT,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US
	56            CN=Google Internet Authority G2,O=Google Inc,C=US 

  

