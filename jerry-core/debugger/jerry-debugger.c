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

#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

#include "jerry-debugger.h"
#include "jerry-port.h"
#include "jcontext.h"
#include "fcntl.h"

/**
 * Debugger socket communication port.
 */
#define PORT 5001

/**
 * Header size in bytes of a websocket package.
 */
#define WEBSOCKET_HEADER_SIZE 2

/**
 * Payload mask size in bytes of a websocket package.
 */
#define WEBSOCKET_MASK_SIZE 4

/**
 * Total header size in bytes of a websocket package.
 */
#define WEBSOCKET_HEADER_TOTAL_SIZE (WEBSOCKET_HEADER_SIZE + WEBSOCKET_MASK_SIZE)

/**
 * Last fragment of a websocket package.
 */
#define WEBSOCKET_FIN_BIT 0x80

/**
 * Masking-key is available.
 */
#define WEBSOCKET_MASK_BIT 0x80

/**
 * Opcode type mask.
 */
#define WEBSOCKET_OPCODE_MASK 0xfu

/**
 * Packet length mask.
 */
#define WEBSOCKET_LENGTH_MASK 0x7fu

/**
 * Websocket opcode types.
 */
typedef enum
{
  WEBSOCKET_TEXT_FRAME = 1, /**< text frame */
  WEBSOCKET_BINARY_FRAME = 2, /**< binary frame */
  WEBSOCKET_CLOSE_CONNECTION = 8, /**< close connection */
  WEBSOCKET_PING = 8, /**< ping (keep alive) frame */
  WEBSOCKET_PONG = 9, /**< reply to ping frame */
} jerry_websocket_opcode_type_t;

/**
 * Convert a 6 bit value to a base-64 character.
 *
 * @return base-64 character
 */
static uint8_t
jerry_to_base64_character (uint8_t value) /**< 6 bit value */
{
  if (value < 26)
  {
    return (uint8_t) (value + 'A');
  }

  if (value < 52)
  {
    return (uint8_t) (value - 26 + 'a');
  }

  if (value < 62)
  {
    return (uint8_t) (value - 52 + '0');
  }

  if (value == 62)
  {
    return (uint8_t) '+';
  }

  return (uint8_t) '/';
} /* jerry_to_base64_character */

/**
 * Encode a byte sequence into base-64 string.
 */
static void
jerry_to_base64 (const uint8_t *source_p, /**< source data */
                 uint8_t *destination_p, /**< destination buffer */
                 size_t length) /**< length of source, must be divisible by 3 */
{
  while (length >= 3)
  {
    uint8_t value = (source_p[0] >> 2);
    destination_p[0] = jerry_to_base64_character (value);

    value = (uint8_t) (((source_p[0] << 4) | (source_p[1] >> 4)) & 0x3f);
    destination_p[1] = jerry_to_base64_character (value);

    value = (uint8_t) (((source_p[1] << 2) | (source_p[2] >> 6)) & 0x3f);
    destination_p[2] = jerry_to_base64_character (value);

    value = (uint8_t) (source_p[2] & 0x3f);
    destination_p[3] = jerry_to_base64_character (value);

    source_p += 3;
    destination_p += 4;
    length -= 3;
  }
}

/**
 * Process WebSocket handshake.
 *
 * @return true is no error is occured
 *         false otherwise
 */
static bool
jerry_process_handshake (int client_socket, /**< client socket */
                         uint8_t *request_buffer_p, /**< temporary buffer */
                         size_t request_buffer_size) /**< size of request buffer */
{
  uint8_t *request_end_p = request_buffer_p;

  /* Buffer request text until the double newlines are received. */
  while (true)
  {
    size_t length = request_buffer_size - 1u - (size_t) (request_end_p - request_buffer_p);

    if (length == 0)
    {
      jerry_port_log (JERRY_LOG_LEVEL_ERROR, "Handshake buffer too small.\n");
      return false;
    }

    ssize_t size = recv (client_socket, request_end_p, length, 0);

    if (size < 0)
    {
      jerry_port_log (JERRY_LOG_LEVEL_ERROR, "Error: %s\n", strerror (errno));
      return false;
    }

    request_end_p += (size_t) size;
    *request_end_p = 0;

    if (request_end_p > request_buffer_p + 4
        && memcmp (request_end_p - 4, "\r\n\r\n", 4) == 0)
    {
      break;
    }
  }

  /* Check protocol. */
  const char *text_p = "GET /jerry-debugger";
  size_t text_len = strlen (text_p);

  if ((size_t) (request_end_p - request_buffer_p) < text_len
      || memcmp (request_buffer_p, text_p, text_len) != 0)
  {
    jerry_port_log (JERRY_LOG_LEVEL_ERROR, "Invalid handshake format.\n");
    return false;
  }

  uint8_t *websocket_key_p = request_buffer_p + text_len;

  text_p = "Sec-WebSocket-Key:";
  text_len = strlen (text_p);

  while (true)
  {
    if ((size_t) (request_end_p - websocket_key_p) < text_len)
    {
      jerry_port_log (JERRY_LOG_LEVEL_ERROR, "Sec-WebSocket-Key not found.\n");
      return false;
    }

    if (websocket_key_p[0] == 'S'
        && websocket_key_p[-1] == '\n'
        && websocket_key_p[-2] == '\r'
        && memcmp (websocket_key_p, text_p, text_len) == 0)
    {
      websocket_key_p += text_len;
      break;
    }

    websocket_key_p++;
  }

  /* String terminated by double newlines. */

  while (*websocket_key_p == ' ')
  {
    websocket_key_p++;
  }

  uint8_t *websocket_key_end_p = websocket_key_p;

  while (*websocket_key_end_p > ' ')
  {
    websocket_key_end_p++;
  }

  /* Since the request_buffer_p is not needed anymore it
   * can be reused for storing the SHA-1 key and base-64 string. */

  const size_t sha1_length = 20;

  jerry_debugger_compute_sha1 (websocket_key_p,
                               (size_t) (websocket_key_end_p - websocket_key_p),
                               (const uint8_t *) "258EAFA5-E914-47DA-95CA-C5AB0DC85B11",
                               36,
                               request_buffer_p);

  /* The SHA-1 key is 20 bytes long but jerry_to_base64 expects
   * a length divisible by 3 so an extra 0 is appended at the end. */
  request_buffer_p[sha1_length] = 0;

  jerry_to_base64 (request_buffer_p, request_buffer_p + sha1_length + 1, sha1_length + 1);

  /* Last value must be replaced by equal sign. */

  text_p = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ";

  if (!jerry_debugger_send ((const uint8_t *) text_p, strlen (text_p)))
  {
    return false;
  }

  if (!jerry_debugger_send (request_buffer_p + sha1_length + 1, 27))
  {
    return false;
  }

  text_p = "=\r\n\r\n";
  return jerry_debugger_send ((const uint8_t *) text_p, strlen (text_p));
} /* jerry_process_handshake */

/*
 * Initialize the socket connection.
 *
 * @return true - if the connection succeeded
 *         false - otherwise.
 */
bool jerry_debugger_socket_init ()
{
  int server_socket;
  struct sockaddr_in addr;
  socklen_t sin_size = sizeof (struct sockaddr_in);

  addr.sin_family = AF_INET;
  addr.sin_port = htons (PORT);
  addr.sin_addr.s_addr = INADDR_ANY;

  if ((server_socket = socket (AF_INET, SOCK_STREAM, 0)) == -1)
  {
    jerry_port_log (JERRY_LOG_LEVEL_ERROR, "Error: %s\n", strerror (errno));
    return false;
  }

  int opt_value = 1;

  if (setsockopt (server_socket, SOL_SOCKET, SO_REUSEADDR, &opt_value, sizeof (int)) == -1)
  {
    close (server_socket);
    jerry_port_log (JERRY_LOG_LEVEL_ERROR, "Error: %s\n", strerror (errno));
    return false;
  }

  if (bind (server_socket, (struct sockaddr *)&addr, sizeof (struct sockaddr)) == -1)
  {
    close (server_socket);
    jerry_port_log (JERRY_LOG_LEVEL_ERROR, "Error: %s\n", strerror (errno));
    return false;
  }

  if (listen (server_socket, 1) == -1)
  {
    close (server_socket);
    jerry_port_log (JERRY_LOG_LEVEL_ERROR, "Error: %s\n", strerror (errno));
    return false;
  }

  jerry_port_log (JERRY_LOG_LEVEL_DEBUG, "Waiting for the client connection.\n");

  if ((JERRY_CONTEXT (debugger_connection) = accept (server_socket, (struct sockaddr *)&addr, &sin_size)) == -1)
  {
    close (server_socket);
    jerry_port_log (JERRY_LOG_LEVEL_ERROR, "Error: %s\n", strerror (errno));
    return false;
  }

  close (server_socket);

  size_t request_buffer_size = 1024;
  bool is_handshake_ok = false;

  JMEM_DEFINE_LOCAL_ARRAY (request_buffer_p, request_buffer_size, uint8_t);

  is_handshake_ok = jerry_process_handshake (JERRY_CONTEXT (debugger_connection),
                                             request_buffer_p,
                                             request_buffer_size);

  JMEM_FINALIZE_LOCAL_ARRAY (request_buffer_p);

  if (!is_handshake_ok)
  {
    close (JERRY_CONTEXT (debugger_connection));
    return false;
  }

  JERRY_DEBUGGER_MESSAGE (jerry_debugger_message_configuration_t, configuration_p);

  union
  {
    uint16_t uint16_value; /**< a 16 bit value */
    uint8_t uint8_value[2]; /**< lower and upper byte of a 16 bit value */
  } endian_data;

  endian_data.uint16_value = 1;

  configuration_p->header.ws_opcode = WEBSOCKET_FIN_BIT | WEBSOCKET_BINARY_FRAME;
  configuration_p->header.size = 3;
  configuration_p->header.type = (uint8_t) JERRY_DEBUGGER_CONFIGURATION;
  configuration_p->cpointer_size = sizeof (jmem_cpointer_t);
  configuration_p->little_endian = (endian_data.uint8_value[0] == 1);

  jerry_debugger_send (JERRY_CONTEXT (debugger_send_buffer),
                       sizeof (jerry_debugger_message_configuration_t));

  int socket_flags = fcntl (JERRY_CONTEXT (debugger_connection), F_GETFL, 0);

  if (socket_flags < 0)
  {
    close (JERRY_CONTEXT (debugger_connection));
    jerry_port_log (JERRY_LOG_LEVEL_ERROR, "Error: %s\n", strerror (errno));
    return false;
  }

  if (fcntl (JERRY_CONTEXT (debugger_connection), F_SETFL, socket_flags | O_NONBLOCK) == -1)
  {
    close (JERRY_CONTEXT (debugger_connection));
    jerry_port_log (JERRY_LOG_LEVEL_ERROR, "Error: %s\n", strerror (errno));
    return false;
  }

  jerry_port_log (JERRY_LOG_LEVEL_DEBUG, "Connected from: %s:%d\n",
                  inet_ntoa (addr.sin_addr), ntohs (addr.sin_port));

  return true;
} /* jerry_debugger_socket_init */

/*
 * Close the socket connection with the client.
 */
void jerry_debugger_connection_end (void)
{
  jerry_port_log (JERRY_LOG_LEVEL_DEBUG, "TCPServer connection closed on port: %d\n", PORT);
  close (JERRY_CONTEXT (debugger_connection));
} /* jerry_debugger_connection_end */

/*
 * Recieve message from the client.
 */
void
jerry_debugger_receive (void)
{
  JERRY_CONTEXT (debugger_message_delay) = JERRY_DEBUGGER_MESSAGE_FREQUENCY;

  uint8_t *recv_buffer_p = JERRY_CONTEXT (debugger_receive_buffer);

  while (true)
  {
    ssize_t byte_recv = recv (JERRY_CONTEXT (debugger_connection),
                              recv_buffer_p + JERRY_CONTEXT (debugger_receive_buffer_offset),
                              JERRY_DEBUGGER_MAX_BUFFER_SIZE - JERRY_CONTEXT (debugger_receive_buffer_offset),
                              0);

    if (byte_recv <= 0)
    {
      return;
    }

    printf("byte_recv: %d\n", byte_recv);

    JERRY_CONTEXT (debugger_receive_buffer_offset) += (uint32_t) byte_recv;

    if (JERRY_CONTEXT (debugger_receive_buffer_offset) < WEBSOCKET_HEADER_TOTAL_SIZE)
    {
      return;
    }

    const size_t max_packet_size = JERRY_DEBUGGER_MAX_BUFFER_SIZE - WEBSOCKET_HEADER_TOTAL_SIZE;

    JERRY_ASSERT (max_packet_size < 126);

    if ((recv_buffer_p[0] & ~WEBSOCKET_OPCODE_MASK) != WEBSOCKET_FIN_BIT
        || (recv_buffer_p[1] & WEBSOCKET_LENGTH_MASK) >= max_packet_size
        || !(recv_buffer_p[1] & WEBSOCKET_MASK_BIT))
    {
      JERRY_CONTEXT (debugger_receive_buffer_offset) = 0;
      return;
    }

    uint32_t message_size = (uint32_t) (recv_buffer_p[1] & WEBSOCKET_LENGTH_MASK);
    uint32_t message_total_size = message_size + WEBSOCKET_HEADER_TOTAL_SIZE;

    if (JERRY_CONTEXT (debugger_receive_buffer_offset) < message_total_size)
    {
      return;
    }

    const uint8_t *mask_p = recv_buffer_p + WEBSOCKET_HEADER_SIZE;
    uint8_t *data_p = recv_buffer_p + WEBSOCKET_HEADER_TOTAL_SIZE;
    const uint8_t *mask_end_p = data_p;
    const uint8_t *data_end_p = data_p + message_size;

    while (data_p < data_end_p)
    {
      *data_p = *data_p ^ *mask_p;

      data_p++;
      mask_p++;

      if (mask_p >= mask_end_p)
      {
        mask_p -= WEBSOCKET_MASK_SIZE;
      }
    }

    /* Process message */
    printf("Message: type: %d size: %d '%s'\n",
           (int) recv_buffer_p[0],
           (int) message_size,
           recv_buffer_p + WEBSOCKET_HEADER_TOTAL_SIZE);

    if (message_total_size < JERRY_CONTEXT (debugger_receive_buffer_offset))
    {
      memcpy (recv_buffer_p,
              recv_buffer_p + message_total_size,
              JERRY_CONTEXT (debugger_receive_buffer_offset) - message_total_size);
    }

    JERRY_CONTEXT (debugger_receive_buffer_offset) -= message_total_size;
  }
} /* jerry_debugger_receive */

/*
 * Send the message to the client side
 *
 * @return true - if the data was send successfully to the client side
 *         false - otherwise.
 */
bool jerry_debugger_send (const uint8_t *data_p, /**< data pointer */
                          size_t data_size) /**< data size */
{
  do
  {
    ssize_t sent_bytes = send (JERRY_CONTEXT (debugger_connection), data_p, data_size, 0);

    if (sent_bytes < 0)
    {
      if (errno == EWOULDBLOCK)
      {
        continue;
      }

      jerry_port_log (JERRY_LOG_LEVEL_ERROR, "Error: %s\n", strerror (errno));
      return false;
    }

    data_size -= (size_t) sent_bytes;
    data_p += sent_bytes;
  }
  while (data_size > 0);

  return true;
} /* jerry_debugger_send */

/**
 * Send the type signal to the client.
 */
void
jerry_debugger_send_type (jerry_debugger_header_type_t type) /**< message type */
{
  JERRY_ASSERT (JERRY_CONTEXT (jerry_init_flags) & JERRY_INIT_DEBUGGER);

  JERRY_DEBUGGER_MESSAGE (jerry_debugger_send_message_header_t, message_header_p);

  message_header_p->ws_opcode = WEBSOCKET_FIN_BIT | WEBSOCKET_BINARY_FRAME;
  message_header_p->size = 1;
  message_header_p->type = (uint8_t) type;

  jerry_debugger_send (JERRY_CONTEXT (debugger_send_buffer),
                       sizeof (jerry_debugger_send_message_header_t));
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

  JERRY_DEBUGGER_MESSAGE (jerry_debugger_send_message_header_t, message_header_p);

  message_header_p->ws_opcode = WEBSOCKET_FIN_BIT | WEBSOCKET_BINARY_FRAME;
  message_header_p->size = (uint8_t) (size + 1);
  message_header_p->type = type;
  memcpy (message_header_p + 1, data, size);

  jerry_debugger_send (JERRY_CONTEXT (debugger_send_buffer),
                       sizeof (jerry_debugger_send_message_header_t) + size);
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

  message_string_p->header.ws_opcode = WEBSOCKET_FIN_BIT | WEBSOCKET_BINARY_FRAME;
  message_string_p->header.size = (uint8_t) (max_fragment_len + 1);
  message_string_p->header.type = message_type;

  while (string_length > max_fragment_len)
  {
    memcpy (message_string_p->string, string_p, max_fragment_len);

    jerry_debugger_send (JERRY_CONTEXT (debugger_send_buffer),
                         sizeof (jerry_debugger_message_string_t));

    string_length -= max_fragment_len;
    string_p += max_fragment_len;
  }

  message_string_p->header.size = (uint8_t) (string_length + 1);

  memcpy (message_string_p->string, string_p, string_length);

  jerry_debugger_send (JERRY_CONTEXT (debugger_send_buffer),
                       sizeof (jerry_debugger_send_message_header_t) + string_length);
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

  byte_code_cptr_p->header.ws_opcode = WEBSOCKET_FIN_BIT | WEBSOCKET_BINARY_FRAME;
  byte_code_cptr_p->header.size = sizeof (jmem_cpointer_t) + 1;
  byte_code_cptr_p->header.type = (uint8_t) type;

  jmem_cpointer_t compiled_code_cp;
  JMEM_CP_SET_NON_NULL_POINTER (compiled_code_cp, compiled_code_p);

  memcpy (byte_code_cptr_p->byte_code_cp, &compiled_code_cp, sizeof (jmem_cpointer_t));

  jerry_debugger_send (JERRY_CONTEXT (debugger_send_buffer),
                       sizeof (jerry_debugger_byte_code_cptr_t));
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
