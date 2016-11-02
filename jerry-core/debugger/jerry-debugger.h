/* Copyright 2016 University of Szeged.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef JERRY_DEBUGGER_H
#define JERRY_DEBUGGER_H

#define MAX_MESSAGE_SIZE 128

/**
* Package header
*/
typdef struct
{
  uint8_t type;                     /**< type of the message */
  uint8_t size;                     /**< size of the message */
} jerry_debug_message_header_t;

/**
* Source file name
*/
typdef struct
{
  jerry_debug_message_header header;    /**< header of the source file name struct */
  char file_name[1];                    /**< the message */
} jerry_debug_message_source_name_t;

#endif /* JERRY_DEBUGGER_H */
