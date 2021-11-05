# home-assistant-device_tracker.edgeos

Home-Assistant device_tracker component for Ubiquiti Edgerouter devices. HEAVILY based on [AsusWRT component](https://github.com/home-assistant/home-assistant/blob/dev/homeassistant/components/device_tracker/asuswrt.py).

The `edgeos` platform offers presence detection by looking at connected devices to an EdgeOS based router.

**This platform is NOT available for Microsoft Windows installations.**

## CONFIGURATION

To use an EdgeOS router in your installation, add the following to your `configuration.yaml` file:

```yaml
# Example configuration.yaml entry
device_tracker:
  - platform: edgeos
    host: YOUR_ROUTER_IP
    username: YOUR_ADMIN_USERNAME
    interval_seconds: 60
    ssh_key: /config/id_rsa
    track_new_devices:  False
```

## CONFIGURATION VARIABLES

**host** *string (required)*  
The IP address of your router, eg. 192.168.1.1.

**username** *string (required)*  
The username of an user with administrative privileges, usually admin.

**password** *string (optional)*  
The password for your given admin account (use this if no SSH key is given).

**protocol** *string (optional, default: ssh)*  
The protocol (ssh or telnet) to use.

**port** *int (optional, default: 22)*  
SSH port to use.

**mode** *string (optional, default: router)*  
The operating mode of the router (router or ap).

**ssh_key** *string (optional)*  
The path to your SSH private key file associated with your given admin account (instead of password).

**require_ip** *boolean (optional, default: True)*  
If the router is in access point mode.

**You need to enable telnet on your router if you choose to use the `telnet` protocol.**

See the [device tracker integration page](https://www.home-assistant.io/integrations/device_tracker) for instructions how to configure the people to be tracked.

## INSTALLATION

Until this is integrated as an actual component, you need to add edgeos.py to /<config dir>/custom_components/device_tracker/ of your Home Assistant.

You can use `track_new_devices: false` so that you don't get one tracker per each device in your network (unless that's what you want!) and then change `track: false` to `track: true` in `known_devices.yaml` for the devices you actually want to track.
