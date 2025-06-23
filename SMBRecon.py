#!/usr/bin/env python3
"""
Description: This script checks SMB share read/write access on multiple hosts using Impacket.
             It connects to each host, enumerates disk shares, and for each share attempts
             to list the root directory (read access) and then upload (and delete) a temporary file
             (write access). For each share where access is available, a CSV report line is written.
             A per-host timeout is applied such that a hung host is terminated after X seconds.
             Hosts that fail DNS resolution are skipped.
Author: 0x48756773 (Johnathan Drozdowski)
Date: 11/06/2025
"""

import argparse
import concurrent.futures
import csv
import io
import signal
import socket
import sys
from contextlib import contextmanager

from impacket.smbconnection import SMBConnection


# --- Timeout helper using signals ---
class TimeoutException(Exception):
    pass


def alarm_handler(signum, frame):
    raise TimeoutException("Function call timed out")


@contextmanager
def time_limit(seconds):
    # Set the signal handler and timer for the current (worker) process.
    signal.signal(signal.SIGALRM, alarm_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)


# --- Our existing check_host function ---
def check_host(host, username, password, domain=''):
    """
    Connect to a host, enumerate disk shares, then test read and write access.
    
    Returns:
        results: A list of tuples (host, share, access)
                 where access is "READ" or "WRITE".
    """
    results = []
    # Create an SMB connection to the host
    smb = SMBConnection(host, host)
    smb.login(username, password, domain)

    # Retrieve the shares using listShares()
    shares = smb.listShares()

    for share in shares:
        # Process only disk shares.
        try:
            if share['shi1_type'] != 0:
                continue
        except Exception as e:
            print(f"[-] [{host}] Error accessing share type: {e}")
            continue

        # Get the share name and strip any trailing null bytes.
        try:
            share_name = share['shi1_netname']
            if isinstance(share_name, bytes):
                share_name = share_name.decode('utf-8', errors='ignore')
            share_name = share_name.rstrip('\x00')
        except Exception as e:
            print(f"[-] [{host}] Error accessing share name: {e}")
            continue

        # Check for read access by attempting to list the share root.
        try:
            smb.listPath(share_name, '*')
            read_access = True
        except Exception:
            read_access = False

        # Try for write access by uploading and then deleting a temporary file.
        write_access = False
        if read_access:
            temp_filename = "impacket_temp_file.txt"
            file_content = b"Temporary test content"
            file_obj = io.BytesIO(file_content)
            try:
                smb.putFile(share_name, temp_filename, file_obj.read)
                smb.deleteFile(share_name, temp_filename)
                write_access = True
            except Exception:
                write_access = False

        if read_access or write_access:
            access = "WRITE" if write_access else "READ"
            results.append((host, share_name, access))
            print(f"[+] [{host}] Share '{share_name}' - {access}")

    smb.logoff()
    return results


def check_host_with_timeout(host, username, password, domain, host_timeout):
    """Wrapper for check_host() that enforces a timeout."""
    try:
        with time_limit(host_timeout):
            return check_host(host, username, password, domain)
    except TimeoutException:
        print(f"[-] [{host}] Timed out after {host_timeout} seconds.")
        return []  # Return empty list if timed out
    except Exception as e:
        print(f"[-] [{host}] Exception: {e}")
        return []


def main():
    print(r"""*************************************************
*                                               *
*                                               *
*   ____  __  __ ____    _             _ _ _    *
*  / ___||  \/  | __ )  / \  _   _  __| (_) |_  *
*  \___ \| |\/| |  _ \ / _ \| | | |/ _` | | __| *
*   ___) | |  | | |_) / ___ \ |_| | (_| | | |_  *
*  |____/|_|  |_|____/_/   \_\__,_|\__,_|_|\__| *
*   0x48756773                                  *
*                                               *
*                                               *
*************************************************
""")
    parser = argparse.ArgumentParser(
        description="SMB access checker using impacket with timeout, periodic updates, and DNS resolution check"
    )
    parser.add_argument("--hostfile", required=True,
                        help="Path to the host list file (one host per line)")
    parser.add_argument("--username", required=True, help="Username for SMB login")
    parser.add_argument("--password", required=True, help="Password for SMB login")
    parser.add_argument("--domain", default='', help="Domain (if applicable)")
    parser.add_argument("--threads", type=int, default=10,
                        help="Number of concurrent processes (default: 10)")
    parser.add_argument("--host-timeout", type=int, default=60,
                        help="Timeout (in seconds) per host check (default: 60)")
    parser.add_argument("--report", default="smb_report.csv",
                        help="Output CSV report file (default: smb_report.csv)")
    args = parser.parse_args()

    # Read hosts from the file (ignoring empty and comment lines).
    try:
        with open(args.hostfile, "r") as f:
            hosts = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    except Exception as e:
        sys.exit(f"Error reading host file: {e}")

    # Filter out hosts that do not resolve.
    resolved_hosts = []
    for host in hosts:
        try:
            socket.gethostbyname(host)
            resolved_hosts.append(host)
        except socket.gaierror as e:
            print(f"[-] Skipping host [{host}] due to DNS resolution failure: {e}")

    if not resolved_hosts:
        sys.exit("No hosts resolved successfully. Exiting.")

    # Write the report header immediately.
    try:
        with open(args.report, "w", newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(["Host", "Share", "Access"])
    except Exception as e:
        sys.exit(f"Error writing report header: {e}")

    # Process hosts concurrently using ProcessPoolExecutor so that hung tasks can be terminated.
    with concurrent.futures.ProcessPoolExecutor(max_workers=args.threads) as executor:
        future_to_host = {
            executor.submit(check_host_with_timeout, host, args.username, args.password, args.domain, args.host_timeout): host
            for host in resolved_hosts
        }
        # For each completed future, immediately update the report.
        for future in concurrent.futures.as_completed(future_to_host):
            host = future_to_host[future]
            try:
                res = future.result()
                if res:
                    # Append results to the report file as soon as the host is processed.
                    try:
                        with open(args.report, "a", newline='') as csvfile:
                            csv_writer = csv.writer(csvfile)
                            for row in res:
                                csv_writer.writerow(row)
                            csvfile.flush()
                    except Exception as e:
                        print(f"[-] Error updating report for host [{host}]: {e}")
            except Exception as e:
                print(f"[-] [{host}] Exception while processing: {e}")

    print(f"[+] Report saved to {args.report}")


if __name__ == "__main__":
    main()
