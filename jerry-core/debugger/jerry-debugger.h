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
#include <stdint.h>

#define MAX_BUFFER_SIZE 128

/**
 * Limited resources available for the engine, so it is important to
 * check the maximum buffer size. It need to be between 64 and 256.
 */
#if MAX_BUFFER_SIZE < 64 || MAX_BUFFER_SIZE > 256
#error "Please define the MAX_BUFFER_SIZE between 64 and 256."
#endif /* MAX_BUFFER_SIZE < 64 || MAX_BUFFER_SIZE > 256 */

/**
 * Calculate how many soruce file name, function name and breakpoint
 * can send in one buffer without overflow.
 */
#define JERRY_DEBUGGER_MAX_SIZE(type) \
 ((MAX_BUFFER_SIZE - sizeof (jerry_debugger_message_header_t)) / sizeof (type))

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
  JERRY_DEBUGGER_BREAKPOINT_LIST,                 /**< there is more piece of the breakpoint list */
  JERRY_DEBUGGER_BREAKPOINT_LIST_END,             /**< the last piece of the breakpoint list
                                                   *   or when one buffer send is enough for the engine */
  JERRY_DEBUGGER_FUNCTION_NAME,                   /**< there is more piece of the function name */
  JERRY_DEBUGGER_FUNCTION_NAME_END,               /**< the last piece of the function name
                                                   *   or when one buffer send is enough for the engine */
  JERRY_DEBUGGER_SOURCE_FILE_NAME,                /**< there is more piece of the source file name */
  JERRY_DEBUGGER_SOURCE_FILE_NAME_END,            /**< if we send the last piece of the source file name
                                                   *   or when one buffer send is enough for the engine  */
  JERRY_DEBUGGER_UNIQUE_START_BYTE_CODE_CPTR,     /**< byte code starter compressed pointer */
} jerry_debugger_header_type_t;

/**
 * Package header
 */
typedef struct
{
  jerry_debugger_header_type_t type; /**< type of the message */
  uint8_t size; /**< size of the message */
} jerry_debugger_message_header_t;

/**
 *  Source file name
 */
typedef struct
{
  jerry_debugger_message_header_t header; /**< header of the message */
  char file_name[JERRY_DEBUGGER_MAX_SIZE (char)]; /**< JavaScript source file name */
} jerry_debugger_message_source_name_t;

/**
 *  Function name
 */
typedef struct
{
  jerry_debugger_message_header_t header; /**< header of the function name struct */
  char function_name[JERRY_DEBUGGER_MAX_SIZE (char)]; /**< the message which contains the function name */
} jerry_debugger_message_function_name_t;

/**
 *  Byte code compressed pointer
 */
typedef struct
{
  jerry_debugger_message_header_t header; /**< header of the struct */
  jmem_cpointer_t byte_code_cp; /**< the byte code compressed pointer */
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
 *  Breakpoint list
 */
typedef struct
{
  jerry_debugger_message_header_t header; /**< header of the struct */
  /** array of the breakpoint pairs */
  jerry_debugger_bp_pairs_t breakpoint_pairs[JERRY_DEBUGGER_MAX_SIZE (jerry_debugger_bp_pairs_t)];
} jerry_debugger_breakpoint_list_t;

#endif /* JERRY_DEBUGGER_H */
