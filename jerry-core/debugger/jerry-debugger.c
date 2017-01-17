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

#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

#include "jerry-debugger.h"
#include "jerry-port.h"
#include "jcontext.h"

#define PORT 5001
#define BACKLOG 1

static int jerry_debugger_connection;    /**< hold the file descriptor for the accepted socket */
uint8_t jerry_debugger_buffer[MAX_BUFFER_SIZE];   /**< buffer for socket communication */

/*
 * Initialize the socket connection
 *
 * @return true - if the connection succeeded
 *         false - otherwise.
 */
bool jerry_debugger_socket_init ()
{
  /* The arguments optval is used to access option values for setsockopt(). */
  bool optval = true;

  int jerry_debugger_socket;  /* socket file descriptor for the remote communication */

  struct sockaddr_in server_addr, client_addr;  /* declarations of the socket address */
  socklen_t sin_size = sizeof (struct sockaddr_in);  /* size of the structure pointed by
                                                      * the server_addr and client_addr */

  /* Server adress declaration */
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons (PORT);
  server_addr.sin_addr.s_addr = INADDR_ANY;
  bzero (&(server_addr.sin_zero), BACKLOG);

  /* Create an endpoint for communication */
  if ((jerry_debugger_socket = socket (AF_INET, SOCK_STREAM, 0)) == -1)
  {
    jerry_port_log (JERRY_LOG_LEVEL_ERROR, "Error: %s\n", strerror (errno));
    return false;
  }

  /* Set the options on socket */
  if (setsockopt (jerry_debugger_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (int)) == -1)
  {
    jerry_port_log (JERRY_LOG_LEVEL_ERROR, "Error: %s\n", strerror (errno));
    return false;
  }

  /* Bind to the server address */
  if (bind (jerry_debugger_socket, (struct sockaddr *)&server_addr, sizeof (struct sockaddr)) == -1)
  {
    jerry_port_log (JERRY_LOG_LEVEL_ERROR, "Error: %s\n", strerror (errno));
    return false;
  }

  /* Listen for connections on socket */
  if (listen (jerry_debugger_socket, BACKLOG) == -1)
  {
    jerry_port_log (JERRY_LOG_LEVEL_ERROR, "Error: %s\n", strerror (errno));
    return false;
  }

  jerry_port_log (JERRY_LOG_LEVEL_DEBUG, "Waiting for the client connection.\n");

  /* Connect from the client */
  if ((jerry_debugger_connection = accept (jerry_debugger_socket, (struct sockaddr *)&client_addr, &sin_size)) == -1)
  {
    jerry_port_log (JERRY_LOG_LEVEL_ERROR, "Error: %s\n", strerror (errno));
    return false;
  }

  close (jerry_debugger_socket);

  jerry_port_log (JERRY_LOG_LEVEL_DEBUG, "Connected from: %s:%d\n",
                  inet_ntoa (client_addr.sin_addr), ntohs (client_addr.sin_port));

  return true;
} /* jerry_debugger_socket_init */

/*
 * Close the socket connection with the client.
 */
void jerry_debugger_connection_end ()
{
  jerry_port_log (JERRY_LOG_LEVEL_DEBUG, "TCPServer connection closed on port: %d\n", PORT);
  close (jerry_debugger_connection);
} /* jerry_debugger_connection_end */

/*
 * Send the message to the client side
 *
 * @return true - if the data was send successfully to the client side
 *         false - otherwise.
 */
bool jerry_debugger_send (size_t data_size) /**< data size */
{
  uint8_t *jerry_debugger_buffer_p = jerry_debugger_buffer;

  ssize_t byte_send = send (jerry_debugger_connection, jerry_debugger_buffer_p, data_size, 0);

  while (byte_send != (ssize_t) data_size)
  {
    if (byte_send == -1)
    {
      jerry_port_log (JERRY_LOG_LEVEL_ERROR, "Error: %s\n", strerror (errno));
      return false;
    }

    data_size -= (size_t) byte_send;
    jerry_debugger_buffer_p += byte_send;

    byte_send += send (jerry_debugger_connection, jerry_debugger_buffer_p, data_size, 0);
  }

  return true;
} /* jerry_debugger_send */

/**
 * Send the type signal to the client.
 */
void
jerry_debugger_send_type (jerry_debugger_header_type_t type) /**< message type */
{
  JERRY_ASSERT (JERRY_CONTEXT (jerry_init_flags) & JERRY_INIT_DEBUGGER);

  JERRY_DEBUGGER_MESSAGE (jerry_debugger_message_header_t, message_header_p);

  message_header_p->type = (uint8_t) type;
  message_header_p->size = 0;

  jerry_debugger_send (sizeof (jerry_debugger_message_header_t));
} /* jerry_debugger_send_type */

/**
 * Send the type signal to the client.
 */
void
jerry_debugger_send_data (jerry_debugger_header_type_t type, /**< message type */
                          const void *data, /**< message data */
                          size_t size) /**< message size */
{
  JERRY_ASSERT (size < JERRY_DEBUGGER_MAX_SIZE (uint8_t));

  JERRY_DEBUGGER_MESSAGE (jerry_debugger_message_header_t, message_header_p);

  message_header_p->type = type;
  message_header_p->size = (uint8_t) size;
  memcpy (message_header_p + 1, data, size);

  jerry_debugger_send (sizeof (jerry_debugger_message_header_t) + size);
} /* jerry_debugger_send_data */

/**
 * Send string to the client.
 */
static void
jerry_debugger_send_string (uint8_t message_type, /**< message type */
                            const jerry_char_t *string_p, /**< content string */
                            size_t string_length) /**< length of content string */
{
  JERRY_ASSERT (JERRY_CONTEXT (jerry_init_flags) & JERRY_INIT_DEBUGGER);

  const size_t max_fragment_len = JERRY_DEBUGGER_MAX_SIZE (char);

  JERRY_DEBUGGER_MESSAGE (jerry_debugger_message_string_t, message_string_p);

  message_string_p->header.type = message_type;
  message_string_p->header.size = (uint8_t) max_fragment_len;

  while (string_length > max_fragment_len)
  {
    memcpy (message_string_p->string, string_p, max_fragment_len);

    jerry_debugger_send (sizeof (jerry_debugger_message_string_t));

    string_length -= max_fragment_len;
    string_p += max_fragment_len;
  }

  message_string_p->header.size = (uint8_t) string_length;

  memcpy (message_string_p->string, string_p, string_length);

  jerry_debugger_send (sizeof (jerry_debugger_message_header_t) + string_length);
} /* jerry_debugger_send_string */

/**
 * Send the function name to the client.
 */
void
jerry_debugger_send_function_name (const jerry_char_t *function_name_p, /**< function name */
                                   size_t function_name_length) /**< length of function name */
{
  JERRY_ASSERT (JERRY_CONTEXT (jerry_init_flags) & JERRY_INIT_DEBUGGER);

  jerry_debugger_send_string (JERRY_DEBUGGER_FUNCTION_NAME, function_name_p, function_name_length);
} /* jerry_debugger_send_function_name */

/**
 * Send the function compressed pointer to the client.
 */
void
jerry_debugger_send_function_cp (jerry_debugger_header_type_t type, /**< message type */
                                 ecma_compiled_code_t *compiled_code_p) /**< byte code pointer */
{
  JERRY_ASSERT (JERRY_CONTEXT (jerry_init_flags) & JERRY_INIT_DEBUGGER);

  JERRY_DEBUGGER_MESSAGE (jerry_debugger_byte_code_cptr_t, byte_code_cptr_p);

  byte_code_cptr_p->header.type = (uint8_t) type;
  byte_code_cptr_p->header.size = sizeof (jmem_cpointer_t);

  jmem_cpointer_t compiled_code_cp;
  JMEM_CP_SET_NON_NULL_POINTER (compiled_code_cp, compiled_code_p);

  memcpy (byte_code_cptr_p->byte_code_cp, &compiled_code_cp, sizeof (jmem_cpointer_t));

  jerry_debugger_send (sizeof (jerry_debugger_byte_code_cptr_t));
} /* jerry_debugger_send_function_cp */

/**
 * Send the file name of the source code to the client.
 */
void
jerry_debugger_send_source_file_name (const jerry_char_t *file_name_p, /**< file name */
                                      size_t file_name_length) /**< length of file name */
{
  if (JERRY_CONTEXT (jerry_init_flags) & JERRY_INIT_DEBUGGER)
  {
    jerry_debugger_send_string (JERRY_DEBUGGER_SOURCE_FILE_NAME, file_name_p, file_name_length);
  }
} /* jerry_debugger_send_source_file_name */
