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
from pprint import pprint # For the readable stack printing

# Define the debugger buffer types
JERRY_DEBUGGER_PARSE_ERROR = 1
JERRY_DEBUGGER_BYTE_CODE_CPTR = 2
JERRY_DEBUGGER_PARSE_FUNCTION = 3
JERRY_DEBUGGER_BREAKPOINT_LIST = 4
JERRY_DEBUGGER_BREAKPOINT_LIST_END = 5
JERRY_DEBUGGER_SOURCE_FILE_NAME = 6
JERRY_DEBUGGER_FUNCTION_NAME = 7
JERRY_DEBUGGER_FREE_BYTE_CODE_CPTR = 8

PORT = 5001
MAX_BUFFER_SIZE = 64  # Need to be the same as the jerry debugger MAX_BUFFER_SIZE
HOST = "localhost"

class JerryDebugger:

    def __init__(self):
        self.message_data = b''
        self.function_list = []
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((HOST, PORT))

    def __del__(self):
        self.client_socket.close()

    def get_message(self):
        if self.message_data == None:
            return None

        while True:
            if len(self.message_data) >= 2:
                size = ord(self.message_data[1])

                if len(self.message_data) >= size + 2:
                    result = self.message_data[0:size + 2]
                    self.message_data = self.message_data[size + 2:]
                    return result

            data = self.client_socket.recv(MAX_BUFFER_SIZE)
            if not data:
                self.message_data = None
                return None

            self.message_data += data

def parse_source(debugger, data):

    source_name = ''
    function_name = ''
    stack = [{}]
    new_function_list = {}

    while True:
        if data == None:
            return

        buffer_type = ord(data[0])
        buffer_size = ord(data[1])

        # print('Buffer type: %d' % buffer_type)
        # print('Message size: %d' % buffer_size)

        if buffer_type == JERRY_DEBUGGER_PARSE_ERROR:
            # Parser error
            return

        if buffer_type == JERRY_DEBUGGER_SOURCE_FILE_NAME:
            source_name += unpack('<%ds' % (buffer_size), data[2:buffer_size+2])[0]

        elif buffer_type == JERRY_DEBUGGER_FUNCTION_NAME:
            function_name += unpack('<%ds' % (buffer_size), data[2:buffer_size+2])[0]

        elif buffer_type == JERRY_DEBUGGER_PARSE_FUNCTION:
            stack.append( { 'name' : function_name, 'source' : source_name } )
            function_name = ''

        elif buffer_type == JERRY_DEBUGGER_BYTE_CODE_CPTR:
            cptr_key = data[2:buffer_size+2]
            stack[-1]['cptr'] = cptr_key
            new_function_list[cptr_key] = stack.pop()

        else:
            #  Parser error
            return

        if len(stack) == 0: # Break the while loop if there is no more data in the stack
            # Empty stack
            break;

        data = debugger.get_message()

    new_function_list[cptr_key]['source'] = source_name # We know the last item in the list is the general byte code
    debugger.function_list = new_function_list # Copy the ready list to the global storage

def release_source(debugger, data, buffer_size):
    del debugger.function_list[data[2:buffer_size+2]]
    # print('Function <%s> bytecode released' % data[2:buffer_size+2])

def main():

    try:
        debugger = JerryDebugger()

    except socket.error as error_msg:
        try:
            errno = error_msg.errno
            msg = str(error_msg)
        except:
            errno = error_msg[0]
            msg = error_msg[1]
        sys.exit('Failed to create the socket. Error: %d %s' % (errno, msg))

    # print('Socket created on: %d' % (PORT))

    while True:

        data = debugger.get_message()

        if not data: # Break the while loop if there is no more data
            break;

        buffer_type = ord(data[0])
        buffer_size = ord(data[1])

        # print('Buffer type: %d and the size: %d' %  (buffer_type, buffer_size))

        if buffer_type in [JERRY_DEBUGGER_PARSE_ERROR,
                           JERRY_DEBUGGER_SOURCE_FILE_NAME,
                           JERRY_DEBUGGER_FUNCTION_NAME,
                           JERRY_DEBUGGER_PARSE_FUNCTION,
                           JERRY_DEBUGGER_BYTE_CODE_CPTR]:
            parse_source(debugger, data)

        elif buffer_type == JERRY_DEBUGGER_FREE_BYTE_CODE_CPTR:
            release_source(debugger, data, buffer_size)

        else:
            print('Feature implementation is in progress...')

    # print('Main debugger function list:')
    # pprint(debugger.function_list)

if __name__ == "__main__":
    main()
