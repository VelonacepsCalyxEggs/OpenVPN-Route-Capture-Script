# OpenVPN Route Capture Script
This application captures retransmitted TCP packets to add them to a .ovpn file. If you have an OpenVPN server, you can use this script to modify your client.ovpn file and add routes to applications that don't work due to regional restrictions, rather than routing your entire PC through the VPN.

## Requirements
To run this script you'll need Python>=3.9 and install the requirements.txt.

Am not sure if the script will run on Linux systems, but if you have a linux machine and not lazy enough to try, give it a shot.

## Usage Example
1. Insert or Edit your .ovpn file in the script's folder.
2. Start the script.
3. Enter the duration for which the script should run.
4. Open the application(s) that can't connect due to regional restrictions.
5. Profit! (hopefully)

Don't forget to re-import configuration for it to apply in the CLIENT!!!

## Tips
You may need to run the script multiple times for a single application.

For instance, with Discord, you might get past the update screen, but the voice servers may still be unresolved. In such cases, run the script again with the VPN and the generated config and try to connect to a voice channel while the script is active.

## Important Notes
1. Imperfect Detection: The script might not detect your Ethernet adapter correctly or might pick the wrong one. If your adapter is not found, please report an issue.

2. Pull Requests Welcome: If you have ideas for improvements and the skills to implement them, feel free to open a pull request.

## Additional info

This script was made mainly for my discord server (Prosto Patka Tier 9001), where users use my OpenVPN server to hang out, so that's why there's a logo, also it's funny.
