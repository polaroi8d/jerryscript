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
import argparse
import logging
from struct import *
from pprint import pprint # For the readable stack printing

# Define the debugger buffer types
JERRY_DEBUGGER_PARSE_ERROR = 1
JERRY_DEBUGGER_BYTE_CODE_CPTR = 2
JERRY_DEBUGGER_PARSE_FUNCTION = 3
JERRY_DEBUGGER_BREAKPOINT_LIST = 4
JERRY_DEBUGGER_BREAKPOINT_OFFSET_LIST = 5
JERRY_DEBUGGER_SOURCE_FILE_NAME = 6
JERRY_DEBUGGER_FUNCTION_NAME = 7
JERRY_DEBUGGER_FREE_BYTE_CODE_CPTR = 8

PORT = 5001
MAX_BUFFER_SIZE = 64  # Need to be the same as the jerry debugger MAX_BUFFER_SIZE
HOST = "localhost"

def arguments_parse():
    parser = argparse.ArgumentParser(description='JerryScript debugger client.')

    parser.add_argument('-v', '--verbose', action='store_true', help='increase verbosity (default: %(default)s)')

    args = parser.parse_args()

    if args.verbose:
       logging.basicConfig(format='%(levelname)s: %(message)s' , level=logging.DEBUG)
       logging.debug('Debug logging mode: ON')

class JerryDebugger:

    def __init__(self):
        self.message_data = b''
        self.function_list = []
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((HOST, PORT))
        self.send_message(b'GET /jerry-debugger HTTP/1.1\r\n' +
                          b'Upgrade: websocket\r\n' +
                          b'Connection: Upgrade\r\n' +
                          b'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n')
        result = b''
        expected = (b'HTTP/1.1 101 Switching Protocols\r\n' +
                    b'Upgrade: websocket\r\n' +
                    b'Connection: Upgrade\r\n' +
                    b'Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n')

        while len(result) < len(expected):
            result += self.client_socket.recv(1024)

        len_result = len(result)
        len_expected = len(expected)

        if result[0:len_expected] != expected:
            raise Exception('Unexpected handshake')

        if len_result > len_expected:
            self.message_data = result[len_expected:]

    def __del__(self):
        self.client_socket.close()

    def send_message(self, message):
        size = len(message)
        while size > 0:
            bytes_send = self.client_socket.send(message)
            if bytes_send < size:
                message = message[bytes_send:]
            size -= bytes_send

    def get_message(self):
        if self.message_data == None:
            return None

        while True:
            if len(self.message_data) >= 2:
                if ord(self.message_data[0]) != 0x82:
                    raise Exception('Unexpected data frame')

                size = ord(self.message_data[1])
                if size == 0 or size >= 126:
                    raise Exception('Unexpected data frame')

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
    stack = [{ 'lines' : [], 'offsets' : []}]
    new_function_list = {}

    while True:
        if data == None:
            return

        buffer_type = ord(data[2])
        buffer_size = ord(data[1]) - 1

        logging.debug('PARSER_SOURCE: buffer type: %d, message size: %d' % (buffer_type, buffer_size))

        if buffer_type == JERRY_DEBUGGER_PARSE_ERROR:
            logging.error('Parser error!')
            return

        if buffer_type == JERRY_DEBUGGER_SOURCE_FILE_NAME:
            source_name += unpack('<%ds' % (buffer_size), data[3:buffer_size+3])[0]

        elif buffer_type == JERRY_DEBUGGER_FUNCTION_NAME:
            function_name += unpack('<%ds' % (buffer_size), data[3:buffer_size+3])[0]

        elif buffer_type == JERRY_DEBUGGER_PARSE_FUNCTION:
            logging.debug('Source name: %s, function name: %s' % (source_name, function_name))
            stack.append( { 'name' : function_name, 'source' : source_name, 'lines' : [], 'offsets' : [] } )
            function_name = ''

        elif buffer_type in [JERRY_DEBUGGER_BREAKPOINT_LIST, JERRY_DEBUGGER_BREAKPOINT_OFFSET_LIST]:
            name = 'lines'
            if buffer_type == JERRY_DEBUGGER_BREAKPOINT_OFFSET_LIST:
                name = 'offsets'

            logging.debug('Breakpoint %s received' % (name))

            buffer_pos = 3
            while buffer_size > 0:
                line = unpack('<I', data[buffer_pos:buffer_pos+4])[0]
                stack[-1][name].append(line)
                buffer_pos += 4
                buffer_size -= 4

        elif buffer_type == JERRY_DEBUGGER_BYTE_CODE_CPTR:
            cptr_key = data[3:buffer_size+3]
            logging.debug('Byte code cptr recieved: {%s}' % (cptr_key))
            stack[-1]['cptr'] = cptr_key
            print(stack[-1])
            new_function_list[cptr_key] = stack.pop()

        else:
            logging.error('Parser error!')
            return

        if len(stack) == 0: # Break the while loop if there is no more data in the stack
            logging.debug('Empty stack.')
            break;

        data = debugger.get_message()

    new_function_list[cptr_key]['source'] = source_name # We know the last item in the list is the general byte code
    debugger.function_list = new_function_list # Copy the ready list to the global storage

def release_source(debugger, data, buffer_size):
    del debugger.function_list[data[3:buffer_size+3]]
    logging.debug('Function {%s} bytecode released' % data[3:buffer_size+3])

def main():
    arguments_parse()

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

    logging.debug('Socket created on: %d' % (PORT))

    while True:

        data = debugger.get_message()

        if not data: # Break the while loop if there is no more data
            break;

        buffer_type = ord(data[2])
        buffer_size = ord(data[1]) - 1

        logging.debug('MAIN buffer type: %d, message size: %d' % (buffer_type, buffer_size))

        if buffer_type in [JERRY_DEBUGGER_PARSE_ERROR,
                           JERRY_DEBUGGER_SOURCE_FILE_NAME,
                           JERRY_DEBUGGER_FUNCTION_NAME,
                           JERRY_DEBUGGER_PARSE_FUNCTION,
                           JERRY_DEBUGGER_BYTE_CODE_CPTR]:
            parse_source(debugger, data)

        elif buffer_type == JERRY_DEBUGGER_FREE_BYTE_CODE_CPTR:
            release_source(debugger, data, buffer_size)

        else:
            logging.debug('Feature implementation is in progress...')

    logging.debug('Main debugger function list:')
    logging.debug(debugger.function_list)

if __name__ == "__main__":
    main()
