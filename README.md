# Retransmitted packet domain resolver.
This application captures retransmitted TCP packets to help track inaccesible domains/IPs. If you have an VPN server with routing, you can use this script to quickly identify the domains that need to be route, rather than routing your entire Client through the Server.

## Requirements
To run this script you'll need Python>=3.9 and install the requirements.txt.

Am not sure if the script will run on Linux systems, but if you have a linux machine and not lazy enough to try, give it a shot.

## Usage Example
1. Start the script.
2. Enter the duration for which the script should run.
3. Open the application(s) / Webpage(s) that can't connect due to regional restrictions.
4. Profit! (hopefully)

## Tips
You may need to run the script multiple times for a single application.

For instance, with Discord, you might get past the update screen, but the voice servers may still be unresolved. In such cases, run the script again with the VPN and the generated config and try to connect to a voice channel while the script is active.

## Important Notes
1. Imperfect Detection: The script might not detect your Ethernet adapter correctly or might pick the wrong one. If your adapter is not found, please report an issue.
> The adapter detection needs some work...

2. Pull Requests Welcome: If you have ideas for improvements and the skills to implement them, feel free to open a pull request.

## Additional info

This script was made mainly for my discord server (Prosto Patka Tier 9001), where users use my VPN server to hang out, so that's why there's a logo, also it's funny.
