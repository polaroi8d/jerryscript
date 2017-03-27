#!/usr/bin/env python

# Copyright JS Foundation and other contributors, http://js.foundation
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

import subprocess
import cmd
import threading
import time

JERRY_BINARY = "./../build/bin/jerry"
JERRY_PYTHON_CLIENT = "./../jerry-debugger/jerry-client-ws.py"

def jerry_binary(self, file):
    subprocess.call(JERRY_BINARY + " --start-debug-server --log-level 3"
                                            + " "
                                            + file, shell=True)

def jerry_client(self):
    subprocess.call(JERRY_PYTHON_CLIENT, shell=True)


class DebuggerShell(cmd.Cmd):

    prompt = "(debugger-shell) "
    file = None

    def close(self):
        if self.file:
            self.file.close()
            self.file = None

    def do_quit(self, arg):
        """ Quit from the debugger shell """
        print('Quiting')
        self.close()
        return True

    def do_run(self, arg):
        if arg == "":
            print("Invalid file input!")

        b = threading.Thread(name='JerryScript Binary', target=jerry_binary(self, arg))
        c = threading.Thread(name='JerryScript Client', target=jerry_client(self))

        try:
            b.start()
            c.start()
        except:
            print("Error: Wrong threading.")

if __name__ == '__main__':
    DebuggerShell().cmdloop()



# testcase = input("What test case do you want to run? ")
# testcase_file = "../tests/debugger/do_" + testcase
# bash_script = "./../tools/runners/run-debugger-test.sh"
# jerry = "./../build/bin/jerry"
# debugger_python = "./../jerry-debugger/jerry-client-ws.py"
# subprocess.call(bash_script + " " + jerry + " " + debugger_python + " " + testcase_file, shell=True)
