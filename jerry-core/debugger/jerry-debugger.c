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

#include "jerry-debugger.h"
#include "jerry-port.h"

#define PORT 5001
#define BLACKLOG 1
#define BUFFER_SIZE 128

int sock;                     /**< return value of socket(), used other methods */
int connected;                /**< return value of the whole socket connection */
ssize_t byte_send;            /**< size of byte_send */
size_t data_len;              /**< data lenght */
bool optval = true;           /**< the arguments optval and optlen are used to access option values for setsockopt() */
char data[BUFFER_SIZE];       /**< data buffer */

struct sockaddr_in server_addr, client_addr;         /**< declarations of the socket address */
socklen_t sin_size = sizeof (struct sockaddr_in);

int remote_init ()
{
  /* Server adress declaration */
  server_addr.sin_family = AF_INET;             /**< the address family is host by order*/
  server_addr.sin_port = htons(PORT);           /**< host to network long (PORT) */
  server_addr.sin_addr.s_addr = INADDR_ANY;     /**< ip address */
  bzero (&(server_addr.sin_zero), BLACKLOG);    /**< sets the first byte of the area starting with zero */

  /* Create an endpoint for communication */
  if ((sock = socket (AF_INET, SOCK_STREAM, 0)) == -1)
  {
      jerry_port_log (JERRY_LOG_LEVEL_ERROR, "Socket error!");
      return -1;
  }

  /* Set the options on socket */
  if (setsockopt (sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (int)) == -1)
  {
      jerry_port_log (JERRY_LOG_LEVEL_ERROR, "Setsockopt error!");
      return -1;
  }

  /* Bind to the server address */
  if (bind (sock, (struct sockaddr *)&server_addr, sizeof (struct sockaddr)) == -1)
  {
      jerry_port_log (JERRY_LOG_LEVEL_ERROR, "Bind error, unable to bind!");
      return -1;
  }

  /* Listen for connections on socket */
  if (listen (sock, BLACKLOG) == -1)
  {
      jerry_port_log (JERRY_LOG_LEVEL_ERROR, "Listen error!");
      return -1;
  }

  jerry_port_log (JERRY_LOG_LEVEL_DEBUG, "Waiting for the client connection.\n");

  /* Connect from the client */
  connected = accept (sock, (struct sockaddr *)&client_addr, &sin_size);

  jerry_port_log (JERRY_LOG_LEVEL_DEBUG,"Connected from: %s:%d\n",
                  inet_ntoa (client_addr.sin_addr),ntohs (client_addr.sin_port));

  return connected;
}

/* Close the socket connection with the client */
void connection_closed()
{
  jerry_port_log (JERRY_LOG_LEVEL_DEBUG, "TCPServer connection closed on port %d.\n", PORT);
  close(connected);
  close(sock);
}


/* Send the parsed file names to the client side */
void send_to_client (const char *data, uint16_t data_len)
{
    byte_send = send (connected, data, data_len, 0);

    /** Check the byte send size with the data because there may be if the
      * package is too big, the socket can't able to send throw the connection.
      */
    if (byte_send != (ssize_t)data_len)
    {
      jerry_port_log (JERRY_LOG_LEVEL_ERROR, "Error, there is some missing package...");
    }
}
