# SMBAudit
This script checks SMB share read/write access on multiple hosts using Impacket.
It connects to each host, enumerates disk shares, and for each share attempts
to list the root directory (read access) and then upload (and delete) a temporary file
(write access). For each share where access is available, a CSV report line is written.
A per-host timeout is applied such that a hung host is terminated after specified seconds.
Hosts that fail DNS resolution are skipped.

usage: smbrecon.py [-h] --hostfile HOSTFILE --username USERNAME --password PASSWORD [--domain DOMAIN] [--threads THREADS] [--host-timeout HOST_TIMEOUT] [--report REPORT]
