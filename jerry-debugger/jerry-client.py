#!/usr/bin/env python

# Copyright 2016 University of Szeged.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import socket
import sys
from struct import *

# Define the debugger buffer types
JERRY_DEBUGGER_BREAKPOINT_LIST = 1
JERRY_DEBUGGER_BREAKPOINT_LIST_END = 2
JERRY_DEBUGGER_FUNCTION_NAME = 3
JERRY_DEBUGGER_FUNCTION_NAME_END = 4
JERRY_DEBUGGER_SOURCE_FILE_NAME = 5
JERRY_DEBUGGER_SOURCE_FILE_NAME_END = 6
JERRY_DEBUGGER_UNIQUE_START_BYTE_CODE_CPTR = 7

PORT = 5001
MAX_BUFFER_SIZE = 64  # Need to be the same as the jerry debugger MAX_BUFFER_SIZE
HOST = "localhost"

def main():
    source_name = ''
    source_name_list = []
    function_name = ''
    function_name_list = []

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((HOST, PORT))
    except socket.error as error_msg:
        try:
            errno = error_msg.errno
            msg = str(error_msg)
        except:
            errno = error_msg[0]
            msg = error_msg[1]
        sys.exit('Failed to create the socket. Error: %d %s' % (errno, msg))
    print('Socket created on: %d' % (PORT))

    while True:
        data = client_socket.recv(MAX_BUFFER_SIZE)

        if not data: #break the while loop if there is no more data
            break;

        buffer_type, buffer_size = unpack('BB', data[:2])
        print('Buffer type: %d' % buffer_type)
        print('Message size: %d' % buffer_size)

        if buffer_type == JERRY_DEBUGGER_SOURCE_FILE_NAME:
            source_name_tmp = unpack('<%ds' % (buffer_size), data[2:buffer_size+2])
            source_name += source_name_tmp[0]

            print('%s' % (source_name_tmp))

        elif buffer_type == JERRY_DEBUGGER_SOURCE_FILE_NAME_END:
            source_name_end = unpack('<%ds' % (buffer_size), data[2:buffer_size+2])
            source_name += source_name_end[0]

            print('%s' % (source_name_end))
            print('Source %s file name parsed.' % (source_name))
            source_name_list.append(source_name)
            source_name = ''

        elif buffer_type == JERRY_DEBUGGER_FUNCTION_NAME:
            function_name_tmp = unpack('<%ds' % (buffer_size), data[2:buffer_size+2])
            function_name += function_name_tmp[0]

            print('%s' % (function_name_tmp))

        elif buffer_type == JERRY_DEBUGGER_FUNCTION_NAME_END:
            function_name_end = unpack('<%ds' % (buffer_size), data[2:buffer_size+2])
            function_name += function_name_end[0]

            print('%s' % (function_name_end))
            print('Function %s parsed.' % (function_name))
            function_name_list.append(function_name)
            function_name = ''

        else:
            print("Feature implementation is processing...")

    client_socket.close()

if __name__ == "__main__":
    main()
