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

#define PORT 5001
#define BACKLOG 1

static int jerry_debugger_connection;    /**< hold the file descriptor for the accepted socket */
uint8_t jerry_debugger_buffer[MAX_BUFFER_SIZE];   /**< buffer for socket communication */

bool jerry_debugger_socket_init ()
{
  /* The arguments optval is used to access option values for setsockopt(). */
  bool optval = true;

  int jerry_debugger_socket;        /**< socket file descriptor for the remote communication */

  struct sockaddr_in server_addr, client_addr;  /**< declarations of the socket address */
  socklen_t sin_size = sizeof (struct sockaddr_in);  /**< size of the structure pointed by
                                                      *   the server_addr and client_addr */

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

/* Close the socket connection with the client */
void jerry_debugger_connection_end ()
{
  jerry_port_log (JERRY_LOG_LEVEL_DEBUG, "TCPServer connection closed on port: %d\n", PORT);
  close (jerry_debugger_connection);
} /* jerry_debugger_connection_end */

/* Send the parsed file names to the client side */
bool jerry_debugger_send (size_t data_len) /**< data length */
{
  ssize_t byte_send = send (jerry_debugger_connection, jerry_debugger_buffer, data_len, 0);

  while (byte_send != (ssize_t) data_len)
  {
    if (byte_send == -1)
    {
      jerry_port_log (JERRY_LOG_LEVEL_ERROR, "Error: %s\n", strerror (errno));
      return false;
    }
    byte_send += send (jerry_debugger_connection, jerry_debugger_buffer, data_len - (size_t) byte_send, 0);
  }
  return true;
} /* jerry_debugger_send */
