#!/usr/bin/env python3
"""
Network Sharing Script
=====================

This script facilitates network sharing between Wi-Fi and Ethernet interfaces on Linux systems.
It handles IP forwarding and iptables rules to enable Internet Connection Sharing (ICS).

Features:
---------
* Enable/disable network sharing between interfaces.
* Automatic interface detection.
* Status checking of current sharing configuration.
* Detailed logging with standard Python logging.
* Interface validation.
* Support for custom IP ranges.
* Automatic detection of active interfaces.
* Backup and restore of iptables rules.

Usage:
------
Basic usage:
    ./network_sharing.py

With specific interfaces:
    ./network_sharing.py --wifi wlan0 --ethernet eth0

List available interfaces:
    ./network_sharing.py --list-interfaces

Check current status:
    ./network_sharing.py --status

Clear rules:
    ./network_sharing.py --clear

Custom IP range:
    ./network_sharing.py --ip-range 192.168.1.0/24

Backup iptables rules:
    ./network_sharing.py --backup rules.backup

Restore iptables rules:
    ./network_sharing.py --restore rules.backup
"""

import sys
import json
import shutil
import logging
import argparse
import ipaddress
import subprocess
from pathlib import Path


class ColorFormatter(logging.Formatter):
    """
    Custom formatter for colored console output with consistent formatting.

    Attributes:
        * COLORS (Dict[str, str]): Mapping of log levels to ANSI color codes.
        * indent_size (int): Number of spaces for indentation.
    """
    COLORS = {
        'DEBUG': '\033[94m',    # Blue
        'INFO': '\033[92m',     # Green
        'WARNING': '\033[93m',  # Yellow
        'ERROR': '\033[91m',    # Red
        'CRITICAL': '\033[91m\033[1m',  # Bold Red
        'RESET': '\033[0m'      # Reset
    }

    def __init__(self, fmt: str | None = None, datefmt: str | None = None) -> None:
        super().__init__(fmt, datefmt)
        self.indent_size = 4  # Consistent indentation size

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record with colored output and indentation.

        Args:
            * record (logging.LogRecord): Log record to format.

        Returns:
            * str: Formatted log message.
        """
        if not sys.stderr.isatty():
            return super().format(record)

        # Store original message
        original_msg = record.msg
        indent = ' ' * self.indent_size

        # Add color to level name
        color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        record.levelname = f"{color}{record.levelname:<7}{self.COLORS['RESET']}"

        # Format the message with proper indentation and structure
        if isinstance(record.msg, str):
            lines = record.msg.split('\n')

            # For command executions and debug messages, keep custom indentation
            if record.levelname.strip() == 'DEBUG':
                record.msg = '\n'.join(f"{indent}{line}" for line in lines)
            else:
                # For INFO and higher, first line remains as is; subsequent lines get indented
                record.msg = lines[0]
                if len(lines) > 1:
                    additional_lines = []
                    for line in lines[1:]:
                        if line.strip():
                            additional_lines.append(f"{indent}{line}")
                    if additional_lines:
                        record.msg += '\n' + '\n'.join(additional_lines)

            # Add color to the first line only
            first_line, *rest = record.msg.split('\n', 1)
            record.msg = f"{color}{first_line}{self.COLORS['RESET']}"
            if rest:
                record.msg += '\n' + rest[0]

        formatted_msg = super().format(record)
        record.msg = original_msg  # Restore original message

        # For non-debug levels, if the output spans multiple lines, wrap it with borders.
        if record.levelno > logging.DEBUG and "\n" in formatted_msg:
            border = "=" * 120
            formatted_msg = f"{border}\n{formatted_msg}\n{border}"
        return formatted_msg


class NetworkSharingError(Exception):
    """
    Custom exception for network sharing errors.
    """
    pass


def setup_logging(debug: bool = False) -> logging.Logger:
    """
    Set up logging configuration with consistent formatting.

    Args:
        * debug (bool): Flag to enable debug logging.

    Returns:
        * logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger('network_sharing')
    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    # Remove any existing handlers
    logger.handlers = []

    # Console handler with improved formatting
    console_handler = logging.StreamHandler(sys.stderr)
    console_formatter = ColorFormatter('%(levelname)s %(message)s')
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.addHandler(console_handler)

    return logger


def format_command_output(output: str, indent: int = 4) -> str:
    """
    Format command output with consistent indentation.

    Args:
        * output (str): Command output string.
        * indent (int): Number of spaces for indentation.

    Returns:
        * str: Formatted command output.
    """
    if not output.strip():
        return output

    lines = output.strip().split('\n')
    indent_str = ' ' * indent

    # For single-line output, return as is
    if len(lines) == 1:
        return output.strip()

    # For multi-line output, indent all lines consistently
    formatted = []
    for line in lines:
        if line.strip():
            formatted.append(f"{indent_str}{line.strip()}")
    return '\n'.join(formatted)


def run_command(command: str, needs_sudo: bool = True, check: bool = True, logger: logging.Logger | None = None) -> str:
    """
    Execute a shell command with consistent output formatting.

    Args:
        * command (str): Shell command to execute.
        * needs_sudo (bool): Flag indicating if sudo is required.
        * check (bool): Flag to enable check on subprocess.run.
        * logger (Optional[logging.Logger]): Logger instance.

    Returns:
        * str: Formatted standard output from command execution.

    Raises:
        * NetworkSharingError: If the command fails.
    """
    try:
        if needs_sudo:
            if not shutil.which('sudo'):
                raise NetworkSharingError("'sudo' is not available on this system")
            command = f"sudo {command}"

        logger.debug(f"Executing command:\n{command}")
        result = subprocess.run(
            command,
            shell=True,
            check=check,
            capture_output=True,
            text=True
        )

        if result.stdout:
            return format_command_output(result.stdout)
        return ""

    except subprocess.CalledProcessError as e:
        error_msg = format_command_output(e.stderr) if e.stderr else str(e)
        raise NetworkSharingError(f"Command failed:\n{error_msg}")


def validate_interface(interface: str, logger: logging.Logger) -> bool:
    """
    Validate if a network interface exists.

    Args:
        * interface (str): Network interface name.
        * logger (logging.Logger): Logger instance.

    Returns:
        * bool: True if interface exists, False otherwise.

    Raises:
        * NetworkSharingError: If the command fails.
    """
    try:
        output = run_command(
            f"ip link show {interface}",
            needs_sudo=False,
            check=False,
            logger=logger
        )
        return "does not exist" not in output.lower()
    except NetworkSharingError:
        return False


def format_interface_list(interfaces: dict[str, list[str]]) -> str:
    """
    Format interface list output with consistent spacing.

    Args:
        * interfaces (dict[str, list[str]]): Dictionary with 'wifi' and 'ethernet' lists.

    Returns:
        * str: Formatted string of available network interfaces.
    """
    lines = [
        "Available Network Interfaces",
        "",
        "WiFi Interfaces:",
        f"    {', '.join(interfaces['wifi']) or 'None'}",
        "",
        "Ethernet Interfaces:",
        f"    {', '.join(interfaces['ethernet']) or 'None'}",
        "",
    ]
    return '\n'.join(lines)


def get_active_interfaces(logger: logging.Logger) -> dict[str, list[str]]:
    """
    Get list of active network interfaces with consistent output formatting.

    Args:
        * logger (logging.Logger): Logger instance.

    Returns:
        * dict[str, list[str]]: Dictionary with keys 'wifi' and 'ethernet' containing interface lists.

    Raises:
        * NetworkSharingError: If interface detection fails.
        * FileNotFoundError: If /proc/net/wireless is not found.
        * IndexError: If /proc/net/wireless is empty.
        * json.JSONDecodeError: If parsing JSON output fails.
    """
    try:
        # First, try to identify wireless interfaces using /proc/net/wireless
        wifi = []
        try:
            with open('/proc/net/wireless', 'r') as f:
                for line in f.readlines()[2:]:  # Skip header lines
                    wifi_if = line.split(':')[0].strip()
                    if wifi_if:
                        wifi.append(wifi_if)
        except (FileNotFoundError, IndexError) as e:
            logger.debug(f"Could not read wireless info from /proc:\n{e}")

        output = run_command("ip -json link show", needs_sudo=False, logger=logger)
        interfaces = json.loads(output)

        if not wifi:
            for iface in interfaces:
                name = iface.get('ifname')
                if not name or name == 'lo':
                    continue
                try:
                    wireless_info = run_command(
                        f"iwconfig {name}",
                        needs_sudo=False,
                        check=False,
                        logger=logger
                    )
                    if "no wireless extensions" not in wireless_info.lower():
                        wifi.append(name)
                except NetworkSharingError:
                    continue

        ethernet = []
        for iface in interfaces:
            name = iface.get('ifname')
            if (not name or name == 'lo' or name in wifi or
                    any(name.startswith(prefix) for prefix in ['veth', 'br', 'docker', 'vbox', 'vmnet'])):
                continue
            if 'ether' in iface.get('link_type', ''):
                ethernet.append(name)

        logger.debug(f"Detected interfaces:\n    WiFi: {wifi}\n    Ethernet: {ethernet}")
        return {'wifi': wifi, 'ethernet': ethernet}
    except (NetworkSharingError, json.JSONDecodeError) as e:
        logger.error(f"Error getting interfaces:\n{e}")
        return {'wifi': [], 'ethernet': []}


def enable_ip_forwarding(logger: logging.Logger) -> None:
    """
    Enable IP forwarding temporarily.

    Args:
        * logger (logging.Logger): Logger instance.

    Raises:
        * NetworkSharingError: If enabling IP forwarding fails.
    """
    logger.info("Enabling IP forwarding...")
    try:
        run_command("sysctl -w net.ipv4.ip_forward=1", logger=logger)
    except NetworkSharingError as e:
        logger.error(f"Failed to enable IP forwarding:\n{e}")
        raise


def format_iptables_output(output: str) -> str:
    """
    Format iptables output for better readability.

    Args:
        * output (str): Raw iptables output.

    Returns:
        * str: Formatted iptables output.
    """
    lines = output.strip().split('\n')
    formatted_lines = []

    for line in lines:
        if not line.strip():
            continue

        if 'Chain' in line:
            formatted_lines.append(line)
            formatted_lines.append('-' * len(line))
            continue

        parts = line.split()
        if len(parts) >= 9:
            formatted = "{:<8}\t{:<8}\t{:<8}\t{:<6}\t{:<8}\t{:<8}\t{:<18}\t{:<18}".format(
                parts[0], parts[1],
                parts[2],
                parts[3],
                parts[4], parts[5],
                parts[6], parts[7]
            )
            if len(parts) > 8:
                formatted += " " + " ".join(parts[8:])
            formatted_lines.append(formatted)

    return '\n'.join(formatted_lines)


def setup_iptables(wifi_interface: str, ethernet_interface: str, ip_range: str = '10.42.0.0/24', logger: logging.Logger | None = None) -> None:
    """
    Set up NAT and forwarding rules with consistent output formatting.

    Args:
        * wifi_interface (str): Wi-Fi interface name.
        * ethernet_interface (str): Ethernet interface name.
        * ip_range (str): IP range for local network.
        * logger (Optional[logging.Logger]): Logger instance.

    Raises:
        * NetworkSharingError: If setting up iptables rules fails.
        * ValueError: If the IP range is invalid.
    """
    logger.info("Setting up iptables rules...")
    try:
        ipaddress.ip_network(ip_range)
        run_command("iptables -t nat -F POSTROUTING", logger=logger)
        run_command(
            f"iptables -D FORWARD -i {wifi_interface} -o {ethernet_interface} "
            "-m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true",
            logger=logger
        )
        run_command(
            f"iptables -D FORWARD -i {ethernet_interface} -o {wifi_interface} "
            "-j ACCEPT 2>/dev/null || true",
            logger=logger
        )

        commands = [
            f"iptables -t nat -A POSTROUTING -o {wifi_interface} -j MASQUERADE",
            f"iptables -A FORWARD -i {wifi_interface} -o {ethernet_interface} "
            "-m state --state RELATED,ESTABLISHED -j ACCEPT",
            f"iptables -A FORWARD -i {ethernet_interface} -o {wifi_interface} -j ACCEPT"
        ]

        for cmd in commands:
            run_command(cmd, logger=logger)

        logger.info("IPTables rules configured successfully")

    except NetworkSharingError as e:
        logger.error(f"Failed to setup iptables rules:\n{e}")
        raise
    except ValueError as e:
        logger.error(f"Invalid IP range:\n{e}")
        raise NetworkSharingError(f"Invalid IP range: {e}")


def clear_rules(wifi_interface: str, ethernet_interface: str, logger: logging.Logger) -> None:
    """
    Clear the NAT and forwarding rules.

    Args:
        * wifi_interface (str): WiFi interface name.
        * ethernet_interface (str): Ethernet interface name.
        * logger (logging.Logger): Logger instance.

    Raises:
        * NetworkSharingError: If clearing rules fails.
    """
    logger.info("Clearing iptables rules...")
    try:
        commands = [
            "iptables -t nat -F POSTROUTING",
            f"iptables -D FORWARD -i {wifi_interface} -o {ethernet_interface} "
            "-m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true",
            f"iptables -D FORWARD -i {ethernet_interface} -o {wifi_interface} "
            "-j ACCEPT 2>/dev/null || true"
        ]

        for cmd in commands:
            run_command(cmd, logger=logger)

        logger.info("Disabling IP forwarding...")
        run_command("sysctl -w net.ipv4.ip_forward=0", logger=logger)

        logger.info("Network sharing disabled successfully")

    except NetworkSharingError as e:
        logger.error(f"Failed to clear rules:\n{e}")
        raise


def backup_rules(filename: str, logger: logging.Logger) -> None:
    """
    Backup current iptables rules to a file.

    Args:
        * filename (str): Path to back up file.
        * logger (logging.Logger): Logger instance.

    Raises:
        * NetworkSharingError: If backup fails.
    """
    try:
        output = run_command("iptables-save", logger=logger)
        Path(filename).write_text(output)
        logger.info(f"Rules backed up to:\n    {filename}")
    except (NetworkSharingError, OSError) as e:
        logger.error(f"Failed to backup rules:\n    {e}")
        raise NetworkSharingError(f"Failed to backup rules: {e}")


def restore_rules(filename: str, logger: logging.Logger) -> None:
    """
    Restore iptables rules from a backup file with built-in cleanup.

    Args:
        * filename (str): Path to back up file.
        * logger (logging.Logger): Logger instance.

    Raises:
        * NetworkSharingError: If restoration fails.
    """
    try:
        if not Path(filename).exists():
            raise NetworkSharingError(f"Backup file {filename} does not exist")

        with open(filename, 'r') as f:
            lines = f.readlines()

        cleaned_lines = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                cleaned_lines.append(line + '\n')

        temp_file = f"{filename}.tmp"
        with open(temp_file, 'w') as f:
            f.writelines(cleaned_lines)

        try:
            logger.debug("First few lines of cleaned rules:")
            for i, line in enumerate(cleaned_lines[:5]):
                logger.debug(f"Line {i + 1}: {repr(line)}")

            run_command(f"iptables-restore < {temp_file}", logger=logger)
            logger.info(f"Rules restored from {filename}")

        finally:
            Path(temp_file).unlink(missing_ok=True)

    except NetworkSharingError as e:
        logger.error(f"Failed to restore rules: {e}")
        raise


def check_status(logger: logging.Logger) -> None:
    """
    Check current status of network sharing with improved output formatting.

    Args:
        * logger (logging.Logger): Logger instance.

    Raises:
        * NetworkSharingError: If status check fails.
    """
    try:
        ip_forward = run_command(
            "cat /proc/sys/net/ipv4/ip_forward",
            needs_sudo=False,
            logger=logger
        ).strip()

        nat_rules = run_command(
            "iptables -t nat -L POSTROUTING -n -v",
            needs_sudo=True,
            logger=logger
        )

        forward_rules = run_command(
            "iptables -L FORWARD -n -v",
            needs_sudo=True,
            logger=logger
        )

        status_output = [
            "Current Network Sharing Status",
            f"IP Forwarding: {'Enabled' if ip_forward == '1' else 'Disabled'}",
            "",
            "NAT Rules:",
            "-" * 20,
            format_iptables_output(nat_rules),
            "",
            "Forward Rules:",
            "-" * 20,
            format_iptables_output(forward_rules)
        ]

        logger.info('\n'.join(status_output))

    except NetworkSharingError as e:
        logger.error(f"Failed to check status:\n    {e}")
        raise


def main() -> None:
    """
    Main function with improved output formatting.

    Raises:
        * SystemExit: If an error occurs during execution.
    """
    parser = argparse.ArgumentParser(
        description='Configure network sharing between WiFi and Ethernet',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('--wifi', help='WiFi interface name')
    parser.add_argument('--ethernet', help='Ethernet interface name')
    parser.add_argument('--clear', action='store_true', help='Clear all rules and disable sharing')
    parser.add_argument('--list-interfaces', action='store_true', help='List available network interfaces')
    parser.add_argument('--status', action='store_true', help='Check current network sharing status')
    parser.add_argument('--ip-range', default='10.42.0.0/24',
                        help='IP range for local network (default: 10.42.0.0/24)')
    parser.add_argument('--backup', metavar='FILE', help='Backup current iptables rules to file')
    parser.add_argument('--restore', metavar='FILE', help='Restore iptables rules from backup file')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')

    args = parser.parse_args()
    logger = setup_logging(args.debug)

    try:
        if args.list_interfaces:
            interfaces = get_active_interfaces(logger)
            logger.info(format_interface_list(interfaces))
            return

        if args.status:
            check_status(logger)
            return

        if args.backup:
            backup_rules(args.backup, logger)
            return

        if args.restore:
            restore_rules(args.restore, logger)
            return

        if not args.wifi or not args.ethernet:
            interfaces = get_active_interfaces(logger)
            if not args.wifi and interfaces['wifi']:
                args.wifi = interfaces['wifi'][0]
                logger.info(f"Auto-detected WiFi interface:\n    {args.wifi}")
            if not args.ethernet and interfaces['ethernet']:
                args.ethernet = interfaces['ethernet'][0]
                logger.info(f"Auto-detected Ethernet interface:\n    {args.ethernet}")

        if not args.wifi or not args.ethernet:
            raise NetworkSharingError(
                "Could not detect required interfaces.\n"
                "Please specify them manually using --wifi and --ethernet options."
            )

        if not validate_interface(args.wifi, logger):
            raise NetworkSharingError(f"WiFi interface does not exist:\n    {args.wifi}")
        if not validate_interface(args.ethernet, logger):
            raise NetworkSharingError(f"Ethernet interface does not exist:\n    {args.ethernet}")

        if args.clear:
            clear_rules(args.wifi, args.ethernet, logger)
        else:
            enable_ip_forwarding(logger)
            setup_iptables(args.wifi, args.ethernet, args.ip_range, logger)

            config_info = [
                "Network sharing enabled successfully",
                "",
                "Client Configuration:",
                f"  IP Range: {args.ip_range}",
                f"  Gateway: {str(ipaddress.ip_network(args.ip_range).network_address + 1)}",
                f"  Subnet Mask: {str(ipaddress.ip_network(args.ip_range).netmask)}"
            ]
            logger.info('\n'.join(config_info))

    except NetworkSharingError as e:
        logger.error(str(e))
        sys.exit(1)
    except Exception as e:
        logger.exception(f"An unexpected error occurred:\n    {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
