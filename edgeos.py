"""
Support for Ubiquiti EdgeOS routers.

HEAVILY based on the AsusWRT component

For more details about this platform, please refer to the documentation at
https://home-assistant.io/components/device_tracker.edgeos/
"""
import logging
import re
import socket
import telnetlib
from collections import namedtuple

import voluptuous as vol

import homeassistant.helpers.config_validation as cv
from homeassistant.components.device_tracker import (
    DOMAIN, PLATFORM_SCHEMA, DeviceScanner)
from homeassistant.const import (
    CONF_HOST, CONF_PASSWORD, CONF_USERNAME, CONF_PORT, 
    CONF_PROTOCOL)

REQUIREMENTS = ['pexpect==4.6.0']

_LOGGER = logging.getLogger(__name__)

CONF_PUB_KEY = 'pub_key'
CONF_SSH_KEY = 'ssh_key'
CONF_REQUIRE_IP = 'require_ip'
DEFAULT_SSH_PORT = 22
SECRET_GROUP = 'Password or SSH Key'

PLATFORM_SCHEMA = vol.All(
    cv.has_at_least_one_key(CONF_PASSWORD, CONF_PUB_KEY, CONF_SSH_KEY),
    PLATFORM_SCHEMA.extend({
        vol.Required(CONF_HOST): cv.string,
        vol.Required(CONF_USERNAME): cv.string,
        vol.Optional(CONF_PROTOCOL, default='ssh'): vol.In(['ssh', 'telnet']),
        vol.Optional(CONF_PORT, default=DEFAULT_SSH_PORT): cv.port,
        vol.Optional(CONF_REQUIRE_IP, default=True): cv.boolean,
        vol.Exclusive(CONF_PASSWORD, SECRET_GROUP): cv.string,
        vol.Exclusive(CONF_SSH_KEY, SECRET_GROUP): cv.isfile,
        vol.Exclusive(CONF_PUB_KEY, SECRET_GROUP): cv.isfile
    }))


_IP_NEIGH_CMD = 'ip neigh'
_IP_NEIGH_REGEX = re.compile(
    r'(?P<ip>([0-9]{1,3}[\.]){3}[0-9]{1,3}|'
    r'([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{1,4}){1,7})\s'
    r'\w+\s'
    r'\w+\s'
    r'(\w+\s(?P<mac>(([0-9a-f]{2}[:-]){5}([0-9a-f]{2}))))?\s'
    r'\s?(router)?'
    r'\s?(nud)?'
    r'(?P<status>(\w+))')


_ARP_CMD = 'show arp | grep -v Address | grep -v incomplete'
_ARP_REGEX = re.compile(
    r'(?P<ip>([0-9]{1,3}[\.]){3}[0-9]{1,3})\s' +
    r'.+\s' +
    r'(?P<mac>(([0-9a-f]{2}[:-]){5}([0-9a-f]{2})))' +
    r'\s' +
    r'.*')

_DHCP_CMD = 'show dhcp leases | tail -n +3'
_DHCP_REGEX = re.compile(
    r'(?P<ip>([0-9]{1,3}[\.]){3}[0-9]{1,3})\s+' +
    r'(?P<mac>(([0-9a-f]{2}[:-]){5}([0-9a-f]{2})))\s+' +
    r'[0-9:/\s]+' +
    r'\w+\s+' +
    r'(?P<name>[a-zA-Z0-9\-\.]*)')


def get_scanner(hass, config):
    """Validate the configuration and return an EdgeOS scanner."""
    scanner = EdgeOSDeviceScanner(config[DOMAIN])

    return scanner if scanner.success_init else None


def _parse_lines(lines, regex):
    """Parse the lines using the given regular expression.

    If a line can't be parsed it is logged and skipped in the output.
    """
    results = []
    for line in lines:
        match = regex.search(line)
        if not match:
            _LOGGER.debug("Could not parse row: %s", line)
            continue
        results.append(match.groupdict())
    return results


Device = namedtuple('Device', ['mac', 'ip', 'name'])


class EdgeOSDeviceScanner(DeviceScanner):
    """This class queries an EdgeOS router."""

    def __init__(self, config):
        """Initialize the scanner."""
        self.host = config[CONF_HOST]
        self.username = config[CONF_USERNAME]
        self.password = config.get(CONF_PASSWORD, '')
        self.ssh_key = config.get('ssh_key', config.get('pub_key', ''))
        self.protocol = config[CONF_PROTOCOL]
        self.port = config[CONF_PORT]
        self.require_ip = config[CONF_REQUIRE_IP]

        if self.protocol == 'ssh':
            self.connection = SshConnection(
                self.host, self.port, self.username, self.password,
                self.ssh_key)
        else:
            self.connection = TelnetConnection(
                self.host, self.port, self.username, self.password)

        self.last_results = {}

        # Test the router is accessible.
        data = self.get_edgeos_data()
        self.success_init = data is not None

    def scan_devices(self):
        """Scan for new devices and return a list with found device IDs."""
        self._update_info()
        return list(self.last_results.keys())

    def get_device_name(self, device):
        """Return the name of the given device or None if we don't know."""
        if device not in self.last_results:
            return None
        return self.last_results[device].name

    def _update_info(self):
        """Ensure the information from the EdgeOS router is up to date.

        Return boolean if scanning successful.
        """
        if not self.success_init:
            return False

        _LOGGER.info('Checking Devices')
        data = self.get_edgeos_data()
        if not data:
            return False

        self.last_results = data
        return True

    def get_edgeos_data(self):
        """Retrieve data from EdgeOS.

        Calls various commands on the router and returns the superset of all
        responses. Some commands will not work on some routers.
        """
        devices = {}
        devices.update(self._get_arp())
        devices.update(self._get_neigh(devices))
        devices.update(self._get_dhcp(devices))

        ret_devices = {}
        for key in devices:
            if not self.require_ip or devices[key].ip is not None:
                ret_devices[key] = devices[key]
        return ret_devices

    def _get_neigh(self, cur_devices):
        lines = self.connection.run_command(_IP_NEIGH_CMD)
        if not lines:
            return {}
        result = _parse_lines(lines, _IP_NEIGH_REGEX)
        devices = {}
        for device in result:
            status = device['status']
            if status is None or status.upper() != 'REACHABLE':
                continue
            if device['mac'] is not None:
                mac = device['mac'].upper()
                old_device = cur_devices.get(mac)
                old_ip = old_device.ip if old_device else None
                devices[mac] = Device(mac, device.get('ip', old_ip), None)
        return devices

    def _get_arp(self):
        lines = self.connection.run_command(_ARP_CMD)
        if not lines:
            return {}
        result = _parse_lines(lines, _ARP_REGEX)
        devices = {}
        for device in result:
            if device['mac'] is not None:
                mac = device['mac'].upper()
                devices[mac] = Device(mac, device['ip'], None)
        return devices

    def _get_dhcp(self, cur_devices):
        lines = self.connection.run_command(_DHCP_CMD)
        if not lines:
            return {}
        result = _parse_lines(lines, _DHCP_REGEX)
        devices = {}
        for device in result:
            print(device)
            if device['mac'] is not None:
                mac = device['mac'].upper()
                old_device = cur_devices.get(mac)
                old_ip = old_device.ip if old_device else None
                devices[mac] = Device(mac, device.get('ip', old_ip), device['name'] or None)
        return devices

class _Connection:
    def __init__(self):
        self._connected = False

    @property
    def connected(self):
        """Return connection state."""
        return self._connected

    def connect(self):
        """Mark current connection state as connected."""
        self._connected = True

    def disconnect(self):
        """Mark current connection state as disconnected."""
        self._connected = False


class SshConnection(_Connection):
    """Maintains an SSH connection to an EdgeOS router."""

    def __init__(self, host, port, username, password, ssh_key):
        """Initialize the SSH connection properties."""
        super().__init__()

        self._ssh = None
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._ssh_key = ssh_key

    def run_command(self, command):
        """Run commands through an SSH connection.

        Connect to the SSH server if not currently connected, otherwise
        use the existing connection.
        """
        from pexpect import pxssh, exceptions

        try:
            if not self.connected:
                self.connect()
            self._ssh.sendline(command)
            self._ssh.prompt()
            lines = self._ssh.before.split(b'\n')[1:-1]
            return [line.decode('utf-8') for line in lines]
        except exceptions.EOF as err:
            _LOGGER.error("Connection refused. %s", self._ssh.before)
            self.disconnect()
            return None
        except pxssh.ExceptionPxssh as err:
            _LOGGER.error("Unexpected SSH error: %s", err)
            self.disconnect()
            return None
        except AssertionError as err:
            _LOGGER.error("Connection to router unavailable: %s", err)
            self.disconnect()
            return None

    def connect(self):
        """Connect to the EdgeOS SSH server."""
        from pexpect import pxssh

        self._ssh = pxssh.pxssh()
        if self._ssh_key:
            self._ssh.login(self._host, self._username, quiet=False,
                            ssh_key=self._ssh_key, port=self._port)
        else:
            self._ssh.login(self._host, self._username, quiet=False,
                            password=self._password, port=self._port)

        super().connect()

    def disconnect(self):
        """Disconnect the current SSH connection."""
        try:
            self._ssh.logout()
        except Exception:  # pylint: disable=broad-except
            pass
        finally:
            self._ssh = None

        super().disconnect()


class TelnetConnection(_Connection):
    """Maintains a Telnet connection to an EdgeOS router."""

    def __init__(self, host, port, username, password):
        """Initialize the Telnet connection properties."""
        super().__init__()

        self._telnet = None
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._prompt_string = None

    def run_command(self, command):
        """Run a command through a Telnet connection.

        Connect to the Telnet server if not currently connected, otherwise
        use the existing connection.
        """
        try:
            if not self.connected:
                self.connect()
            self._telnet.write('{}\n'.format(command).encode('ascii'))
            data = (self._telnet.read_until(self._prompt_string).
                    split(b'\n')[1:-1])
            return [line.decode('utf-8') for line in data]
        except EOFError:
            _LOGGER.error("Unexpected response from router")
            self.disconnect()
            return None
        except ConnectionRefusedError:
            _LOGGER.error("Connection refused by router. Telnet enabled?")
            self.disconnect()
            return None
        except socket.gaierror as exc:
            _LOGGER.error("Socket exception: %s", exc)
            self.disconnect()
            return None
        except OSError as exc:
            _LOGGER.error("OSError: %s", exc)
            self.disconnect()
            return None

    def connect(self):
        """Connect to the EdgeOS Telnet server."""
        self._telnet = telnetlib.Telnet(self._host)
        self._telnet.read_until(b'login: ')
        self._telnet.write((self._username + '\n').encode('ascii'))
        self._telnet.read_until(b'Password: ')
        self._telnet.write((self._password + '\n').encode('ascii'))
        self._prompt_string = self._telnet.read_until(b'#').split(b'\n')[-1]

        super().connect()

    def disconnect(self):
        """Disconnect the current Telnet connection."""
        try:
            self._telnet.write('exit\n'.encode('ascii'))
        except Exception:  # pylint: disable=broad-except
            pass

        super().disconnect()
