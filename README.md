# home-assistant-device_tracker.edgeos
Home-Assistant device_tracker component for Ubiquiti Edgerouter devices

HEAVILY based on [AsusWRT component](https://github.com/home-assistant/home-assistant/blob/dev/homeassistant/components/device_tracker/asuswrt.py)


The `edgeos` platform offers presence detection by looking at connected devices to a EDGEOS based router.

`This platform is NOT available for Microsoft Windows installations.`

**CONFIGURATION**

To use an EdgeOS router in your installation, add the following to your configuration.yaml file:
```
# Example configuration.yaml entry
device_tracker:
  - platform: edgeos
    host: YOUR_ROUTER_IP
    username: YOUR_ADMIN_USERNAME
```

**CONFIGURATION VARIABLES**

```
host
(string)(Required)The IP address of your router, eg. 192.168.1.1.
username
(string)(Required)The username of an user with administrative privileges, usually admin.
password
(string)(Optional)The password for your given admin account (use this if no SSH key is given).
protocol
(string)(Optional)The protocol (ssh or telnet) to use.
Default value: ssh
port
(int)(Optional)SSH port to use.
Default value: 22
mode
(string)(Optional)The operating mode of the router (router or ap).
Default value: router
ssh_key
(string)(Optional)The path to your SSH private key file associated with your given admin account (instead of password).
require_ip
(boolean)(Optional)If the router is in access point mode.
Default value: true
```

`You need to enable telnet on your router if you choose to use protocol: telnet.`

See the [device tracker component](https://www.home-assistant.io/components/device_tracker/) page for instructions how to configure the people to be tracked.

**INSTALLATION**

Until this is integrated as an actual component, you need to add edgeos.py to /<config dir>/custom_components/device_tracker/ of your Home Assistant.
