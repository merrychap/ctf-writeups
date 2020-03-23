#!/bin/bash
exec 2>/dev/null
/home/tmpfs/server &
timeout -k 5 30 /home/tmpfs/client