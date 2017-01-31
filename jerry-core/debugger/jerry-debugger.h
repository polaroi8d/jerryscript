/* Copyright JS Foundation and other contributors, http://js.foundation
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

#ifdef JERRY_DEBUGGER

#include "jmem-allocator.h"
#include "ecma-globals.h"

/* Jerry debugger protocol is the simplified version of RFC-6455 (WebSockets). */

#define JERRY_DEBUGGER_MAX_BUFFER_SIZE 128

#define JERRY_DEBUGGER_MESSAGE_FREQUENCY 5

bool jerry_debugger_accept_connection (void);
void jerry_debugger_close_connection (bool log_error);
bool jerry_debugger_send (const uint8_t *data_p, size_t data_size);

void jerry_debugger_compute_sha1 (const uint8_t *input1, size_t input1_len,
                                  const uint8_t *input2, size_t input2_len,
                                  uint8_t output[20]);

/**
 * Limited resources available for the engine, so it is important to
 * check the maximum buffer size. It need to be between 64 and 256.
 */
#if JERRY_DEBUGGER_MAX_BUFFER_SIZE < 64 || JERRY_DEBUGGER_MAX_BUFFER_SIZE > 256
#error "Please define the MAX_BUFFER_SIZE between 64 and 256."
#endif /* JERRY_DEBUGGER_MAX_BUFFER_SIZE < 64 || JERRY_DEBUGGER_MAX_BUFFER_SIZE > 256 */

/**
 * Calculate the maximum number of items for a given type
 * can one message hold.
 */
#define JERRY_DEBUGGER_MAX_SIZE(type) \
 ((JERRY_DEBUGGER_MAX_BUFFER_SIZE - sizeof (jerry_debugger_send_message_header_t)) / sizeof (type))

/**
 * Type cast the debugger send buffer into a specific type.
 */
#define JERRY_DEBUGGER_SEND_MESSAGE(type, name_p) \
  type *name_p = ((type *) &JERRY_CONTEXT (debugger_send_buffer))

/**
 * Type cast the debugger receive buffer into a specific type.
 */
#define JERRY_DEBUGGER_RECEIVE_MESSAGE(type, name_p) \
  type *name_p = ((type *) &JERRY_CONTEXT (debugger_receive_buffer))

/**
 * Types for the package.
 */
typedef enum
{
  /* Messages sent by the server to client. */
  JERRY_DEBUGGER_CONFIGURATION = 1, /**< debugger configuration */
  JERRY_DEBUGGER_PARSE_ERROR = 2, /**< parse error */
  JERRY_DEBUGGER_BYTE_CODE_CP = 3, /**< byte code compressed pointer */
  JERRY_DEBUGGER_PARSE_FUNCTION = 4, /**< parsing a new function */
  JERRY_DEBUGGER_BREAKPOINT_LIST = 5, /**< list of line offsets */
  JERRY_DEBUGGER_BREAKPOINT_OFFSET_LIST = 6, /**< list of byte code offsets */
  JERRY_DEBUGGER_RESOURCE_NAME = 7, /**< resource name fragment */
  JERRY_DEBUGGER_FUNCTION_NAME = 8, /**< function name fragment */
  JERRY_DEBUGGER_FREE_BYTE_CODE_CP = 9, /**< invalidate byte code compressed pointer */
  JERRY_DEBUGGER_BREAKPOINT_HIT = 10, /**< notify breakpoint hit */
  JERRY_DEBUGGER_BACKTRACE = 11, /**< backtrace data */
  JERRY_DEBUGGER_BACKTRACE_END = 12, /**< last backtrace data */

  /* Messages sent by the client to server. */
  JERRY_DEBUGGER_UPDATE_BREAKPOINT = 0, /**< update breakpoint status */
  JERRY_DEBUGGER_STOP = 1, /**< stop execution */
  JERRY_DEBUGGER_CONTINUE = 2, /**< continue execution */
  JERRY_DEBUGGER_STEP = 3, /**< next breakpoint, step into functions */
  JERRY_DEBUGGER_NEXT = 4, /**< next breakpoint in the same context */
  JERRY_DEBUGGER_GET_BACKTRACE = 5, /**< get backtrace */
} jerry_debugger_header_type_t;

/**
 * Header for outgoing packets.
 */
typedef struct
{
  uint8_t ws_opcode; /**< websocket opcode */
  uint8_t size; /**< size of the message */
  uint8_t type; /**< type of the message */
} jerry_debugger_send_message_header_t;

/**
 * Header for incoming packets.
 */
typedef struct
{
  uint8_t ws_opcode; /**< websocket opcode */
  uint8_t size; /**< size of the message */
  uint8_t mask[4]; /**< mask bytes */
  uint8_t type; /**< type of the message */
} jerry_debugger_receive_message_header_t;

/**
 * String (Source file name or function name).
 */
typedef struct
{
  jerry_debugger_send_message_header_t header; /**< message header */
  uint8_t cpointer_size; /**< size of compressed pointers */
  uint8_t little_endian; /**< little endian machine */
} jerry_debugger_message_send_configuration_t;

/**
 * String (Source file name or function name).
 */
typedef struct
{
  jerry_debugger_send_message_header_t header; /**< message header */
  uint8_t string[JERRY_DEBUGGER_MAX_SIZE (uint8_t)]; /**< string data */
} jerry_debugger_message_send_string_t;

/**
 * Byte code compressed pointer.
 */
typedef struct
{
  jerry_debugger_send_message_header_t header; /**< message header */
  uint8_t byte_code_cp[sizeof (jmem_cpointer_t)]; /**< byte code compressed pointer */
} jerry_debugger_message_send_byte_code_cptr_t;

/**
 * Notify breakpoint hit.
 */
typedef struct
{
  jerry_debugger_send_message_header_t header; /**< message header */
  uint8_t byte_code_cp[sizeof (jmem_cpointer_t)]; /**< byte code compressed pointer */
  uint8_t offset[sizeof (uint32_t)]; /**< breakpoint offset */
} jerry_debugger_message_send_breakpoint_hit_t;

/**
 * Send backtrace.
 */
typedef struct
{
  jerry_debugger_send_message_header_t header; /**< message header */
  jerry_debugger_frame_t frames[JERRY_DEBUGGER_MAX_SIZE (jerry_debugger_frame_t)]; /**< frames */
} jerry_debugger_message_send_backtrace_t;

/**
 * Update (enable/disable) breakpoint status.
 */
typedef struct
{
  jerry_debugger_receive_message_header_t header; /**< message header */
  uint8_t is_set_breakpoint; /**< set or clear breakpoint */
  uint8_t byte_code_cp[sizeof (jmem_cpointer_t)]; /**< byte code compressed pointer */
  uint8_t offset[sizeof (uint32_t)]; /**< breakpoint offset */
} jerry_debugger_message_receive_update_breakpoint_t;

/**
 * Get backtrace.
 */
typedef struct
{
  jerry_debugger_receive_message_header_t header; /**< message header */
  uint8_t max_depth[sizeof (uint32_t)]; /**< maximum depth (0 - unlimited) */
} jerry_debugger_message_receive_get_backtrace_t;

/**
 * Stack frame descriptor used by backtrace.
 */
typedef struct
{
  uint8_t byte_code_cp[sizeof (jmem_cpointer_t)]; /**< byte code compressed pointer */
  uint8_t offset[sizeof (uint32_t)]; /**< last breakpoint offset */
} jerry_debugger_frame_t;

bool jerry_debugger_receive (void);
void jerry_debugger_send_type (jerry_debugger_header_type_t type);
void jerry_debugger_send_data (jerry_debugger_header_type_t type, const void *data, size_t size);
void jerry_debugger_send_string (uint8_t message_type, const jerry_char_t *string_p, size_t string_length);
void jerry_debugger_send_function_name (const jerry_char_t *function_name_p, size_t function_name_length);
void jerry_debugger_send_function_cp (jerry_debugger_header_type_t type, ecma_compiled_code_t *compiled_code_p);
void jerry_debugger_send_source_file_name (const jerry_char_t *file_name_p, size_t file_name_length);

void jerry_debugger_breakpoint_hit (void);

#endif /* JERRY_DEBUGGER */

#endif /* JERRY_DEBUGGER_H */
