nmcli dev disconnect wlan0
service network-manager stop
ifconfig wlan0 down
iwconfig wlan0 mode monitor
ifconfig wlan0 up
