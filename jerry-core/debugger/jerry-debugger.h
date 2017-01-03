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

#include "jmem-allocator.h"
#include "ecma-globals.h"

#define MAX_BUFFER_SIZE 64

extern uint8_t jerry_debugger_buffer[MAX_BUFFER_SIZE];

extern bool jerry_debugger_socket_init (void);
extern void jerry_debugger_connection_end (void);
extern bool jerry_debugger_send (size_t data_len);

/**
 * Limited resources available for the engine, so it is important to
 * check the maximum buffer size. It need to be between 64 and 256.
 */
#if MAX_BUFFER_SIZE < 64 || MAX_BUFFER_SIZE > 256
#error "Please define the MAX_BUFFER_SIZE between 64 and 256."
#endif /* MAX_BUFFER_SIZE < 64 || MAX_BUFFER_SIZE > 256 */

/**
 * Calculate how many source file name, function name and breakpoint
 * can send in one buffer without overflow.
 */
#define JERRY_DEBUGGER_MAX_SIZE(type) \
 ((MAX_BUFFER_SIZE - sizeof (jerry_debugger_message_header_t)) / sizeof (type))

/**
 * Type cast the debugger buffer into a specific type.
 */
#define JERRY_DEBUGGER_MESSAGE(type, name_p) \
  type *name_p = ((type *) &jerry_debugger_buffer)

/**
 * Types for the package
 *
 * This helps the debugger to decide what type of the data come
 * from the JerryScript. If the buffer size is not enough for
 * the message the engine split it up into many pieces. The header
 * of the last piece has a type with an '_END' postfix.
 */
typedef enum
{
  JERRY_DEBUGGER_PARSE_ERROR = 1,                     /**< parse error */
  JERRY_DEBUGGER_BYTE_CODE_CPTR = 2,                  /**< byte code compressed pointer */
  JERRY_DEBUGGER_PARSE_FUNCTION = 3,                  /**< parsing a new function */
  JERRY_DEBUGGER_BREAKPOINT_LIST = 4,                 /**< there is more piece of the breakpoint list */
  JERRY_DEBUGGER_BREAKPOINT_LIST_END = 5,             /**< the last piece of the breakpoint list
                                                       *   or when one buffer send is enough for the engine */
  JERRY_DEBUGGER_SOURCE_FILE_NAME = 6,                /**< source file name fragment */
  JERRY_DEBUGGER_FUNCTION_NAME = 7,                   /**< function name fragment */
  JERRY_DEBUGGER_FREE_BYTE_CODE_CPTR = 8,             /**< invalidate byte code compressed pointer */
} jerry_debugger_header_type_t;

/**
 * Package header
 */
typedef struct
{
  uint8_t type; /**< type of the message */
  uint8_t size; /**< size of the message */
} jerry_debugger_message_header_t;

/**
 * String (Source file name or function name)
 */
typedef struct
{
  jerry_debugger_message_header_t header; /**< header of the message */
  char string[JERRY_DEBUGGER_MAX_SIZE (char)]; /**< string */
} jerry_debugger_message_string_t;

/**
 * Byte code compressed pointer
 */
typedef struct
{
  jerry_debugger_message_header_t header; /**< header of the struct */
  uint8_t byte_code_cp[sizeof (jmem_cpointer_t)]; /**< the byte code compressed pointer */
} jerry_debugger_byte_code_cptr_t;

/**
 * Breakpoint pairs
 */
typedef struct
{
  uint32_t offset; /**< breakpoint line offset */
  uint32_t line; /**< breakpoint line index */
} jerry_debugger_bp_pairs_t;

/**
 * Breakpoint list
 */
typedef struct
{
  jerry_debugger_message_header_t header; /**< header of the struct */
  /** array of the breakpoint pairs */
  jerry_debugger_bp_pairs_t breakpoint_pairs[JERRY_DEBUGGER_MAX_SIZE (jerry_debugger_bp_pairs_t)];
} jerry_debugger_breakpoint_list_t;

extern void jerry_debugger_send_type (jerry_debugger_header_type_t type);
extern void jerry_debugger_send_function_name (const jerry_char_t *function_name_p, size_t function_name_length);
extern void jerry_debugger_send_function_cp (jerry_debugger_header_type_t type, ecma_compiled_code_t *compiled_code_p);
extern void jerry_debugger_send_source_file_name (const jerry_char_t *file_name_p, size_t file_name_length);

#endif /* JERRY_DEBUGGER_H */
