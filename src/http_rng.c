/* vim: set expandtab cindent fdm=marker ts=2 sw=2: */

/* {{{ Copyright notice

Copyright (C) 2011-2013 Jirka Hladky <hladky DOT jiri AT gmail DOT com>

This file is part of CSRNG http://code.google.com/p/csrng/

CSRNG is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

CSRNG is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with CSRNG.  If not, see <http://www.gnu.org/licenses/>.
}}} */

// {{{ Includes and constants (defines)
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <sys/mman.h>   //mlock
#include <signal.h>

#include <time.h>

#include <pthread.h>
#include <inttypes.h>
#include <assert.h>
#include <regex.h>
#include <csprng/helper_utils.h>
#include <csprng/http_rng.h>
#include <csprng/fips.h>
#include <csprng/qrbg-c.h>

#define MAXLEN 300
#define ZERO_ROUNDS_LIMIT 12
//}}}

//{{{Global variables
const char* const http_random_source_names[HTTP_COUNT] = { "HOTBITS", "RANDOM.ORG", "RANDOMNUMBERS.INFO", "QRBG-random.irb.hr" };
const char* const http_random_source_server[HTTP_COUNT] = { "www.fourmilab.ch", "www.random.org", "www.randomnumbers.info", "random.irb.hr" };
const char* const http_random_source_port[HTTP_COUNT] = { "80", "80", "80", "1227" };
//For testing using local server
//const char* const http_random_source_server[HTTP_COUNT] = { "localhost", "www.random.org", "www.randomnumbers.info", "random.irb.hr" };
//const char* const http_random_source_port[HTTP_COUNT] = { "8080", "80", "80", "1227" };

typedef struct {
  http_random_source_t source;
  http_random_state_t* state;
} http_random_thread_arg_t;

typedef struct {
  http_random_source_t* source;
  uint8_t** data;
  int* sock;
  regex_t* html_regex;
  char* html_regex_populated;
  struct addrinfo** resolve_addr;
  struct addrinfo** resolve_addr_p;
  struct QRBG** p_QRBG;
  char* verbosity;
} http_random_producer_cancel_t;

typedef struct {
  char* name;
  size_t size;
  uint8_t mlocked;
} string_with_mlock;

static string_with_mlock QRBG_RNG_user;
static string_with_mlock QRBG_RNG_passwd;

static pthread_t thread[HTTP_COUNT];  //0=> HOTBITS, 1=>RANDOM_ORG, 2=>RANDOMNUMBERS_INFO
static pthread_cond_t empty, fill;    //Signals to control multiple producers/ one consumer
static pthread_mutex_t mutex;         //Guards access control to http_random_state_t

static pthread_mutex_t state_mutex;                //Guards acces control to thread_running array
static pthread_cond_t state_cond;                  //Signal that thread state has changed
static http_random_thread_state_t thread_running[HTTP_COUNT] = { 0 }; //Index 0=> HOTBITS, 1=>RANDOM_ORG, 2=>RANDOMNUMBERS_INFO .
static http_random_thread_arg_t input[HTTP_COUNT];

//static uint8_t http_random_source_mask[HTTP_COUNT] = { 1, 2, 4 , 8 };
static uint8_t http_random_source_mask[HTTP_COUNT] = { MASK_HOTBITS, MASK_RANDOM_ORG, MASK_RANDOMNUMBERS_INFO, MASK_QRBG };

static uint8_t init = 0;                        //Only one init is allowed
//}}}

//{{{ static uint32_t bitmask (uint8_t num_of_bits) 
// Creates 32-bit bitmask with num_of_bits (least significant bits) set to 1
static uint32_t bitmask (uint8_t num_of_bits)
{
  static const uint32_t masks[33] = {
    0x00000000UL, 0x00000001UL, 0x00000003UL, 0x00000007UL,
    0x0000000fUL, 0x0000001fUL, 0x0000003fUL, 0x0000007fUL,
    0x000000ffUL, 0x000001ffUL, 0x000003ffUL, 0x000007ffUL,
    0x00000fffUL, 0x00001fffUL, 0x00003fffUL, 0x00007fffUL,
    0x0000ffffUL, 0x0001ffffUL, 0x0003ffffUL, 0x0007ffffUL,
    0x000fffffUL, 0x001fffffUL, 0x003fffffUL, 0x007fffffUL,
    0x00ffffffUL, 0x01ffffffUL, 0x03ffffffUL, 0x07ffffffUL,
    0x0fffffffUL, 0x1fffffffUL, 0x3fffffffUL, 0x7fffffffUL,
    0xffffffffUL };

  if (num_of_bits < 33)
    return masks[num_of_bits];
  else
    return 0xffffffffUL; 
}
//}}}

//{{{ static uint32_t bitmask_offset (uint8_t num_of_bits, uint8_t offset)
//Creates 32-bit mask with num_of_bits set to 1
//offset least significant bits are set to 0 then num_of_bits is set 1 
//and remaining most significatn bits are set to 0
static uint32_t bitmask_offset (uint8_t num_of_bits, uint8_t offset)
{
  if ( num_of_bits <= 32 && offset <= 32 && num_of_bits + offset <= 32 )
    return bitmask(num_of_bits) << offset;
  else
    return 0;
}
//}}}

//{{{ static void safe_sleep(unsigned long sec, char source)
//Thread safe sleep which does not interfere with alarm signal
//Link with -lrt
static void safe_sleep(unsigned long sec, uint8_t source, char verbosity)
{
  pthread_mutex_lock( &state_mutex );
  thread_running[source] = STATE_SLEEPING;
  pthread_cond_signal( &state_cond);
  pthread_mutex_unlock( &state_mutex);


  //Index 0 => current time
  //Index 1 => stop time
  struct timespec ts[2];
  time_t tt[2];
  struct tm broken_time[2]; 
  struct timespec req={0,0};

  clock_gettime(CLOCK_REALTIME, &ts[0]);

  ts[1].tv_nsec = ts[0].tv_nsec;
  ts[1].tv_sec  = ts[0].tv_sec + sec;

  tt[0] = ts[0].tv_sec;
  tt[1] = ts[1].tv_sec;

  gmtime_r(&tt[0], &broken_time[0]);
  gmtime_r(&tt[1], &broken_time[1]);

  //random.org will reset quota just after midnight at UTC. Make sure that we will wake-up shortly after midnight to do the check
  if (  broken_time[1].tm_yday >  broken_time[0].tm_yday || broken_time[1].tm_year >  broken_time[0].tm_year ) {
    //New day - finish sleep at time 1:15AM. 
    if ( broken_time[1].tm_hour * 60 + broken_time[1].tm_min > 75 ) {
       ts[1].tv_sec  -=  ( broken_time[1].tm_hour * 60 + broken_time[1].tm_min - 75 ) * 60;
    }
  }

  if ( verbosity > 1 ) fprintf( stderr, "safe_sleep for %s: sleeping for %ld seconds\n", http_random_source_names[source], (long int) (ts[1].tv_sec) - (long int) (ts[0].tv_sec) );
  req.tv_sec=ts[1].tv_sec - ts[0].tv_sec;
  while(nanosleep(&req,&req)==-1)
    continue;

  pthread_mutex_lock( &state_mutex );
  thread_running[source] = STATE_RUNNING;
  pthread_cond_signal( &state_cond);
  pthread_mutex_unlock( &state_mutex);
}
//}}}

//{{{ static int ipow(int base, uint8_t exp)
//Return base ^ exp
static int ipow(int base, uint8_t exp)
{
  int result = 1;
  while (exp) {
    if (exp & 1) result *= base;
    exp >>= 1;
    base *= base;
  }

  return result;
}
//}}}

//{{{ int random_org_quota()
/*
http://www.random.org/quota/?format=plain check

The Guidelines for Automated Clients specify that you should use the Quota Checker periodically to verify that your client
is not issuing requests for random numbers to the RANDOM.ORG server when its quota is exhausted. For most clients, the easiest
solution is to interleave the quota checks with the requests for random numbers. If a quota check returns a negative value,
your client should back off for at least ten minutes before issuing another quota check. Only when the quota check returns a zero
or positive value, should your client resume its requests for random numbers. If you want to build a really well-behaved client,
you can implement an exponential backoff algorithm with a maximum delay of 24 hours.

The types of errors can vary. Errors will occur if you specify invalid parameters but can also occur because the server is temporarily
overloaded. Reasonable behaviour for a client is to look for the "Error:" string in the page returned by the server and print out
the whole line if the string was present. When I get around to it, I will provide a full list of possible errors on this page.
In the meantime, feel free to experiment ;-)

Return value of this function:
-1 => ERROR
 0 => We are allowed to get data from www.random.org
 1 => Quota has been exhausted for today. Wait upto 24 hours before it will be refilled
*/

int random_org_quota()
{
  pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

  int  sock;
  int n;
  unsigned int i;
  char request[MAXLEN], buf[MAXLEN];
  struct timeval timeout;      
  timeout.tv_sec = 60;
  timeout.tv_usec = 0;
  long int value;
  regex_t html_regex;
  char *endptr;
  int return_status = 0;
  char html_regex_populated = 0;
  int rc;
  struct addrinfo *resolve_addr = NULL;
  struct addrinfo *resolve_addr_p = NULL;
  struct addrinfo hints;
  char timed_out_counter;


  //hints for getaddrinfo
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_STREAM; /* Stream socket */
  hints.ai_flags = 0;
  hints.ai_protocol = 0;           /* Any protocol */

  //Prepare the request to send to the checkbuf cgi script
  memset(request, 0, MAXLEN);
  if ( snprintf(request, MAXLEN - 1, "GET /quota/?format=plain\nHost: %s\nUser-Agent: %s\n\n", http_random_source_server[RANDOM_ORG_RNG], USERAGENT) > MAXLEN -1 ) {
    fprintf(stderr, "ERROR: random_org_quota: snprintf: buffer too small, request string \"%s\" has been truncated\n", request);
    return_status = -1;
    goto end_of_random_org_quota;
  }

  rc = getaddrinfo(http_random_source_server[RANDOM_ORG_RNG], http_random_source_port[RANDOM_ORG_RNG], &hints, &resolve_addr);
  if (rc != 0) {
    fprintf(stderr, "ERROR: random_org_quota: %s. getaddrinfo has failed: %s\n", http_random_source_names[RANDOM_ORG_RNG], gai_strerror(rc));
    goto end_of_random_org_quota;
  }

  /* getaddrinfo() returns a list of address structures.
     Try each address until we successfully connect(2).
     If socket(2) (or connect(2)) fails, we (close the socket
     and) try the next address.
     */

  for (resolve_addr_p = resolve_addr; resolve_addr_p != NULL; resolve_addr_p = resolve_addr_p->ai_next) {
    sock = socket(resolve_addr_p->ai_family, resolve_addr_p->ai_socktype, resolve_addr_p->ai_protocol);
    if (sock == -1) continue;
    if (setsockopt (sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) continue; 
    if (setsockopt (sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0) continue;
    if (connect(sock, resolve_addr_p->ai_addr, resolve_addr_p->ai_addrlen) != -1) break; /* Success */
    close(sock);
  }

  if (resolve_addr_p == NULL) {               /* No address succeeded */
    fprintf(stderr, "ERROR: random_org_quota: %s. Cannot connect to the server %s. Network address resolve has failed.\n", http_random_source_names[RANDOM_ORG_RNG], http_random_source_server[RANDOM_ORG_RNG] );
    goto end_of_random_org_quota;
  }

  //Send the request to checkbuf cgi script
  if (write(sock, request, strlen(request)) == -1) {
    fprintf(stderr, "ERROR: random_org_quota: cannot write to socket. Reported error: %s\n", strerror(errno));
    return_status = -1;
    goto end_of_random_org_quota;
  }

  //Read data returned
  i = 0;
  timed_out_counter = 0;
  while ( sizeof (buf) / sizeof(buf[0]) -1  > i ) {
    n = read(sock, &buf[i], sizeof (buf) / sizeof(buf[0]) -1 -i );
    if ( n > 0 ) {
      i += n;
      continue;
    } else if ( n == 0 ) {
      //fprintf(stderr, "INFO: random_org_quota: read from socket: EOF\n");
      break;

    } else if ( errno == EAGAIN ) {
      fprintf(stderr, "WARNING: random_org_quota: read from socket has timed out.\n"); 
      ++timed_out_counter;
      if ( timed_out_counter > 2 ) break;
      continue;
    } else if ( errno == EWOULDBLOCK ) {
      fprintf(stderr, "WARNING: random_org_quota: read from socket: %s. Trying again to read data from the socket.\n",
          strerror(errno) );
      continue;
    } else {
      fprintf(stderr, "ERROR: random_org_quota: read from socket: %s\n", strerror(errno) );
      break;
    }
  }
  close(sock);

  if (i == 0) {
    fprintf(stderr, "ERROR: random_org_quota: cannot read from socket. Reported error: %s\n", strerror(errno));
    return_status = -1;
    goto end_of_random_org_quota;
  }

  if ( i > sizeof (buf) / sizeof(buf[0]) - 1 ) {
    fprintf(stderr,"ERROR: random_org_quota: Read %u bytes of data where at most %d bytes where expected.\n", i, (int) (sizeof (buf) / sizeof(buf[0]) - 1) );
    return_status = -1;
    goto end_of_random_org_quota;
  };
  buf[i] = 0;

  //Check for "Error"
  if ( regcomp(&html_regex, "Error", REG_ICASE | REG_NOSUB ) ) {
    fprintf(stderr, "ERROR: random_org_quota: Could not compile regex \"Error\"\n");
    return_status = -1;
    goto end_of_random_org_quota;
  } else {
    html_regex_populated = 1;
  }

  if ( regexec(&html_regex, buf, 0, NULL, 0) == 0 ) {
    fprintf(stderr, "ERROR: random_org_quota: Site has returned following error message: \"%s\".\n", buf);
    return_status = -1;
    goto end_of_random_org_quota;
  }

  value = strtol(buf, &endptr, 10);
  if ( (endptr == buf)  || errno == ERANGE ) {
    fprintf(stderr, "ERROR: random_org_quota: strtol parsing string \"%s\".\n", buf);
    return_status = -1;
    goto end_of_random_org_quota;
  }

  if ( value > 0 ) {
    return_status = 0;
  } else {
    return_status = 1;
  }

end_of_random_org_quota:
  if ( html_regex_populated ) regfree ( &html_regex );
  if ( resolve_addr != NULL ) freeaddrinfo(resolve_addr);
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
  return return_status;
}
//}}}

//{{{ void http_random_producer_cleanup (void *arg)
void http_random_producer_cleanup (void *arg) {
  http_random_producer_cancel_t *input = (http_random_producer_cancel_t *) arg;

  if ( *input->verbosity > 1 ) fprintf(stderr, "http_random_producer_cleanup for %s\n", http_random_source_names[*input->source]);
  if ( *input->data != NULL ) free(*input->data);
  if ( *input->resolve_addr != NULL ) freeaddrinfo(*input->resolve_addr);
  *input->resolve_addr = NULL;
  *input->resolve_addr_p = NULL;
  if ( *input->sock != -1 ) close(*input->sock);
  if ( *input->html_regex_populated) regfree(input->html_regex);
  if ( *input->p_QRBG != NULL ) deleteQRBG(*input->p_QRBG);
  *input->p_QRBG = NULL;

  pthread_mutex_lock( &state_mutex );
  thread_running[*input->source] = STATE_FINISHED;
  pthread_cond_signal( &state_cond );
  pthread_mutex_unlock( &state_mutex );

}
//}}}

//{{{ void mux_cleanup(void *arg)
void mux_cleanup(void *arg) {
  pthread_mutex_t *m;
  m = (pthread_mutex_t *) arg;
  pthread_mutex_unlock(m);
}
//}}}

//{{{ static void reset_string_with_mlock ( string_with_mlock *d )
 static void reset_string_with_mlock ( string_with_mlock *d )
{
  d->name = NULL;
  d->size = 0;
  d->mlocked = 0;
}
//}}}

//{{{ static void clear_string_with_mlock ( string_with_mlock *d )
 static void clear_string_with_mlock ( string_with_mlock *d )
{
  //fprintf(stderr, "clear_string_with_mlock\n");
  if (  d->name != NULL ) {
    if ( d->mlocked == 1 ) {
      if ( munlock(d->name, d->size) ) fprintf(stderr, "WARNING: clear_string_with_mlock: munlock has failed.  Reported error: %s\n", strerror(errno));
    }
    free(d->name);
  } 

  reset_string_with_mlock(d);
}
//}}}

//{{{ static void delete_name_and_password ()
static void delete_name_and_password ()
{
  //fprintf(stderr, "delete_name_and_password\n");
  clear_string_with_mlock(&QRBG_RNG_user);
  clear_string_with_mlock(&QRBG_RNG_passwd);
}
//}}}

//{{{ static uint8_t set_string_with_mlock ( string_with_mlock *d, const char* input )
 static uint8_t set_string_with_mlock ( string_with_mlock *d, const char* input)
{
  size_t len;

  //fprintf(stderr, "set_string_with_mlock with string %s\n", input);
  reset_string_with_mlock(d);

  len = strlen (input) + 1;

  d->name = calloc (len, sizeof (char));
  if ( d->name == NULL ) { 
    fprintf(stderr, "ERROR: set_string_with_mlock: calloc has failed for buffer of size %zu. Reported error: %s\n", len, strerror(errno));
    return 1;
  }
  d->size = len;

  if ( mlock(d->name, len) ) {
    fprintf(stderr, "WARNING: set_string_with_mlock: mlock has failed for buffer of size %zu. Reported error: %s\n", len, strerror(errno));
    d->mlocked = 0;
  } else {
    d->mlocked = 1;
  }

  strncpy (d->name, input, len-1);

  return 0;

}
//}}}

//{{{ static uint8_t copy_name_and_password (const char* QRBG_RNG_user_input,  const char* QRBG_RNG_passwd_input)
static uint8_t copy_name_and_password (const char* QRBG_RNG_user_input,  const char* QRBG_RNG_passwd_input)
{
  //fprintf(stderr, "copy_name_and_password\n");
  if ( set_string_with_mlock(&QRBG_RNG_user,   QRBG_RNG_user_input) == 0 && 
       set_string_with_mlock(&QRBG_RNG_passwd, QRBG_RNG_passwd_input) == 0 ) {
    return 0;
  } else {
    delete_name_and_password();
    return 1;
  }
    
}
//}}}

//{{{ static void* http_random_producer( void *arg_ptr )
static void* http_random_producer( void *arg_ptr ) {
  pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
  pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

//{{{ Init
  volatile size_t size, buf_size;        //How much bytes can we request, local buffer size
  uint8_t *data, *end;                   //Local buffer
  volatile size_t valid_data;            //Amount of valid bytes in the local buf
  volatile unsigned int zero_round = 0;  //Count fatal ERRORs

  int n;
  int rc;
  struct timeval timeout;      
  timeout.tv_sec = 60;
  timeout.tv_usec = 0;
  const time_t min_sleep = 60;   //TODO: 600
  const time_t max_sleep = 14400;
  volatile time_t sleeptime = min_sleep;
  uint8_t first_run=1;          //TRUE
  uint8_t data_added;
  char verbosity;
  char html_regex_populated = 0;
  char timed_out_counter;

  char request[MAXLEN];
  char html_regex_string[MAXLEN];
  struct addrinfo hints;
  struct addrinfo *resolve_addr, *resolve_addr_p;

  int sock=-1;
  http_random_thread_arg_t* input;

  regex_t html_regex;
  regmatch_t pmatch;
  struct QRBG* p_QRBG=NULL;
  http_random_producer_cancel_t http_random_producer_cancel;


  pthread_mutex_lock( &mutex );
  input = ( http_random_thread_arg_t* ) arg_ptr;
  http_random_source_t source = input->source;
  http_random_state_t* state = input->state;
  verbosity = state->verbosity;
  pthread_mutex_unlock( &mutex );


  if ( source < HTTP_COUNT ) {
    pthread_mutex_lock( &state_mutex );
    thread_running[source] = STATE_RUNNING;
    pthread_cond_signal( &state_cond);
    pthread_mutex_unlock( &state_mutex);
  } else {
    return NULL;
  }
  
  data = NULL;
  resolve_addr = NULL;
  resolve_addr_p = NULL;
  
  if ( verbosity > 0) fprintf(stderr, "INFO: http_random_producer: starting thread %s\n", http_random_source_names[source]);


/* push the cleanup routine  onto the thread
   cleanup stack.  This routine will be called when the 
   thread is cancelled.  Also note that the pthread_cleanup_push
   call must have a matching pthread_cleanup_pop call.  The
   push and pop calls MUST be at the same lexical level 
   within the code */

  http_random_producer_cancel.source = &source;
  http_random_producer_cancel.data = &data;
  http_random_producer_cancel.sock = &sock;
  http_random_producer_cancel.html_regex = &html_regex;
  http_random_producer_cancel.html_regex_populated = &html_regex_populated;
  http_random_producer_cancel.resolve_addr = &resolve_addr;
  http_random_producer_cancel.resolve_addr_p = &resolve_addr_p;
  http_random_producer_cancel.p_QRBG = &p_QRBG;
  http_random_producer_cancel.verbosity = &state->verbosity;


  pthread_cleanup_push( http_random_producer_cleanup, (void *)&http_random_producer_cancel );
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

  //hints for getaddrinfo
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_STREAM; /* Stream socket */
  hints.ai_flags = 0;
  hints.ai_protocol = 0;           /* Any protocol */
//}}}

//{{{ Prepare HTML request string  
  switch (source) {
    case HOTBITS_RNG:
      size = 2048;             //Number of expected bytes
      buf_size = size + 1;     //Buffer size

      memset(request, 0, MAXLEN);
      if ( snprintf(request, MAXLEN - 1, "GET /cgi-bin/uncgi/Hotbits?nbytes=%zu&fmt=bin\nHost: %s\nUser-Agent: %s\n\n", size, http_random_source_server[source], USERAGENT) > MAXLEN -1 ) {
        fprintf(stderr, "ERROR: http_random_producer: snprintf: buffer too small, request string \"%s\" has been truncated\n", request);
        goto end_of_http_random_producer;
      }
      break;

    case RANDOM_ORG_RNG:
      size = 8192;
      buf_size = size + 1;

      memset(request, 0, MAXLEN);
      if ( snprintf(request, MAXLEN - 1, "GET /cgi-bin/randbyte?nbytes=%zu&format=f\nHost: %s\nUser-Agent: %s\n\n", size, http_random_source_server[source], USERAGENT) > MAXLEN -1 ) {
        fprintf(stderr, "ERROR: http_random_producer: snprintf: buffer too small, request string \"%s\" has been truncated\n", request);
        goto end_of_http_random_producer;
      }
      break;

    case RANDOMNUMBERS_INFO_RNG:
      size=1000;               //Format HTML. Size is the number of expected numbers
      buf_size = 8193;         //Size of HTML document

      memset( &pmatch, 0, sizeof(regmatch_t));

      snprintf(html_regex_string, MAXLEN - 1, "( [0-9]{1,4}){%zu}", size);
      html_regex_string[ MAXLEN - 1] = 0;
      if ( regcomp(&html_regex, html_regex_string, REG_EXTENDED) ) {
        fprintf(stderr, "ERROR: http_random_producer: Could not compile regex \"%s\"\n", html_regex_string);
        goto end_of_http_random_producer;
      } else {
        html_regex_populated = 1;
      }

      memset(request, 0, MAXLEN);
      if ( snprintf(request, MAXLEN - 1, "GET /cgibin/wqrng.cgi?limit=%lu&amount=%zu HTTP/1.0\nHost: %s\nUser-Agent: %s\n\n",
          RANDOMNUMBERS_INFO_MAX, size, http_random_source_server[RANDOMNUMBERS_INFO_RNG], USERAGENT) > MAXLEN -1 ) {
        fprintf(stderr, "ERROR: http_random_producer: snprintf: buffer too small, request string \"%s\" has been truncated\n", request);
        goto end_of_http_random_producer;
      }
      break;
    case QRBG_RNG:
      size = 4096;             //Expected number of bytes
      buf_size = size;         //Local buffer size. See DEFAULT_CACHE_SIZE in src/QRBG.h
                               //We don't need regexec/strstr functions, so buf_size == size

      p_QRBG = newQRBG();
      if (p_QRBG == NULL ) {
        fprintf(stderr,"ERROR: http_random_producer: newQRBG failure\n");
        goto end_of_http_random_producer;
      }
      rc = defineServerQRBG(p_QRBG, http_random_source_server[source], strtol(http_random_source_port[source], NULL, 10));
      if ( rc ) {
        fprintf(stderr, "ERROR: http_random_producer: defineServerQRBG failure\n");
        goto end_of_http_random_producer;
      }

      rc = defineUserQRBG(p_QRBG, QRBG_RNG_user.name, QRBG_RNG_passwd.name);
      if ( rc ) {
        fprintf(stderr, "ERROR: http_random_producer: defineUserQRBG failure\n");
        goto end_of_http_random_producer;
      }
      delete_name_and_password();

      break;


    default:
      fprintf(stderr,"ERROR: http_random_producer: unexpected source specification %c.\n", source);
      goto end_of_http_random_producer;
  }

  //Allocate local buffer
  data = calloc(buf_size, sizeof(uint8_t) );
  if ( data == NULL ) {
    fprintf(stderr, "ERROR: http_random_producer: Dynamic memory allocation has failed for buffer of size %zu. Reported error: %s\n", 
        buf_size * sizeof(uint8_t), strerror(errno));
    goto end_of_http_random_producer;
  }
//}}}

//{{{ Main loop. Send HTML request, get and parse data, perform FIPS test and put data to the buffer
  while( 1 ) {

    if ( verbosity > 1 && zero_round > 0 ) fprintf(stderr, "INFO: http_random_producer: %s. Number of successive ERRORs is %d.\n", http_random_source_names[source], zero_round);

    if ( zero_round >= ZERO_ROUNDS_LIMIT ) {
      fprintf (stderr, "ERROR: http_random_producer: %s. Number of ERRORS in row has reached the limit of %d. Ending the thread.\n", http_random_source_names[source], zero_round);
      goto end_of_http_random_producer;
    }

    if ( first_run == 0 ) {

      if ( zero_round == 0 ) {
        //Reset sleep time to min value
        sleeptime = min_sleep;
      }

      if ( sleeptime > max_sleep ) sleeptime = max_sleep;
      safe_sleep( sleeptime, source, verbosity );

      //ERROR has occured. Make sleeptime exponentially longer
      if ( zero_round > 0 ) {
        sleeptime *= 2;
      }

    } else {
      first_run = 0;
    }

    valid_data = 0;
    data[buf_size-1] = 0;  //NULL terminate the string - see strstr and regexec functions
    end = data;

//{{{ QRBG_RNG - request is already encapsulated in getBytesQRBG
    if ( source == QRBG_RNG ) {
      pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

      //Expecting valid_data == 0, end == data 
      n = getBytesQRBG(p_QRBG, end, buf_size - valid_data);

      if ( n == 0 ) {
        ++zero_round;
        fprintf (stderr, "ERROR: http_random_producer: %s. getBytesQRBG: Got zero bytes %u times in row. Retrying.\n", 
            http_random_source_names[source], zero_round);
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        continue;
      }

      if ( n <  (int) (buf_size - valid_data) ) {
        fprintf(stderr, "WARNING: http_random_producer: %s. getBytesQRBG: Requested %zu bytes, got %d bytes.\n",
            http_random_source_names[source], buf_size - valid_data, n);
        //fwrite(end, n, 1, stdout);
        //TODO: we will not use incomplete data until local buffer FIPS validation is implemented
        ++zero_round;
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        continue;
      } 

      //fwrite(end, n, 1, stdout);
      end += n;
      valid_data += n;
      pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
      //}}}

      //{{{ ALL OTHER SOURCES - need to create socket and parse the output
    } else {

      //{{{ Resolve hostname
      rc = getaddrinfo(http_random_source_server[source], http_random_source_port[source], &hints, &resolve_addr);
      if (rc != 0) {
        fprintf(stderr, "ERROR: http_random_producer: %s. getaddrinfo has failed: %s\n", http_random_source_names[source], gai_strerror(rc));
        ++zero_round;
        continue;
      }

      /* getaddrinfo() returns a list of address structures.
         Try each address until we successfully connect(2).
         If socket(2) (or connect(2)) fails, we (close the socket
         and) try the next address.
         */

      for (resolve_addr_p = resolve_addr; resolve_addr_p != NULL; resolve_addr_p = resolve_addr_p->ai_next) {
        sock = socket(resolve_addr_p->ai_family, resolve_addr_p->ai_socktype, resolve_addr_p->ai_protocol);
        if (sock == -1) continue;
        if (setsockopt (sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) continue; 
        if (setsockopt (sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0) continue;
        if (connect(sock, resolve_addr_p->ai_addr, resolve_addr_p->ai_addrlen) != -1) break; /* Success */
        close(sock);
      }

      if (resolve_addr_p == NULL) {               /* No address succeeded */
        fprintf(stderr, "ERROR: http_random_producer: %s. Cannot connect to the server %s. Network address resolve has failed.\n", http_random_source_names[source], http_random_source_server[source] );
        ++zero_round;
        continue;
      }

      //}}}

      //{{{ RANDOM_ORG_RNG = quota check first
      //TODO: see http://www.random.org/clients/http/ and switch to the newest API
      if ( source == RANDOM_ORG_RNG ) {
        if (random_org_quota() > 0 ) {
          ++zero_round;
          continue;
        }
      }
      //}}}

      //{{{ Send request, read data sent back
      if (write(sock, request, strlen(request)) == -1) {
        fprintf(stderr, "ERROR: http_random_producer: %s. write to socket has failed with: %s\n", http_random_source_names[source], strerror(errno) );
        ++zero_round;
        continue;
      }

      //Read random data returned
      timed_out_counter = 0;
      while ( buf_size - 1> valid_data ) {
        n = read(sock, end, buf_size - 1 - valid_data);
        if ( n > 0 ) {
          //fwrite(end, n, 1, stdout);
          end += n;
          valid_data += n;
          continue;
        } else if ( n == 0 ) {
          //EOF
          break;
        } else if ( errno == EAGAIN ) {
          if ( verbosity > 0 ) fprintf(stderr, "WARNING: http_random_producer: %s. read from socket has timed out.\n", 
              http_random_source_names[source] );
          ++timed_out_counter;
          if ( timed_out_counter > 2 ) break;
          continue;
        } else if ( errno == EWOULDBLOCK ) {
          if ( verbosity > 0 ) fprintf(stderr, "WARNING: http_random_producer: %s. read from socket: %s. Trying again to read data from the socket.\n",
              http_random_source_names[source], strerror(errno) );
          continue;
        } else {
          fprintf(stderr, "ERROR: http_random_producer: %s. read from socket: %s\n", http_random_source_names[source], strerror(errno) );
          break;
        }
      }

      close(sock);
      sock = -1;

      if ( valid_data == 0 ) {
        fprintf(stderr, "ERROR: http_random_producer: cannot read from socket. Reported error: %s\n", strerror(errno));
        ++zero_round;
        continue;
      }

      if ( valid_data > buf_size - 1) {
        fprintf(stderr,"ERROR: http_random_producer: %s. Read %zu bytes of data where at most %zu bytes where expected.\n",http_random_source_names[source], valid_data, buf_size - 1);
        ++zero_round;
        continue;
      };
      *end = 0;    //NULL TERMINATE THE STRING - this to be able to manipulate with it as with string
      //}}}

      //{{{ Parse HTML from RANDOMNUMBERS_INFO_RNG   
      if ( source == RANDOMNUMBERS_INFO_RNG) {
        char *saveptr, *token, *str_input;
        char found = 0;

        saveptr = NULL;
        for (str_input = (char *)data ; ; str_input= NULL) {
          token = strtok_r(str_input, "\n", &saveptr);
          if (token == NULL) break;
          if ( regexec(&html_regex, token, 1, &pmatch, 0) == 0 ) {
            found = 1;
            break;
          }
        }

        if ( found == 0 ) {
          fprintf(stderr, "ERROR: http_random_producer: %s. No match of regexp \"%s\"\n", http_random_source_names[source], html_regex_string);
          //fprintf(stderr, "\n%s\n", data);
          ++zero_round;
          continue;
        }// else {
        //  printf("Matched substring \"%.*s\" is found at position %d to %d.\n",
        //       pmatch.rm_eo - pmatch.rm_so, &token[(int)pmatch.rm_so],
        //       (int) pmatch.rm_so, (int) pmatch.rm_eo - 1 );
        //}

        token =  &token[(int)pmatch.rm_so];
        //fprintf(stderr, "\n%s\n\n\n\n", token);

        long int value;
        uint32_t raw_data = 0;
        uint8_t unprocessed_raw_data_length = 0;
        uint8_t remainder;
        char *endptr;
        size_t expected_size;

        valid_data = 0;
        end = data;
        expected_size = (int) ( (double) size * (double) RANDOMNUMBERS_INFO_BITS / 8.0 );
        assert(expected_size < buf_size );

        while( valid_data <= expected_size ) {
          value = strtol(token, &endptr, 10);
          if ( (endptr == token)  || errno == ERANGE || (value < 0) || (value > (long int) RANDOMNUMBERS_INFO_MAX )) break;
          //fprintf(stderr, "%ld ", value);
          raw_data |= (uint32_t) value;
          unprocessed_raw_data_length += RANDOMNUMBERS_INFO_BITS;
          while (unprocessed_raw_data_length >= 8 ) {
            remainder = unprocessed_raw_data_length - 8;
            data[valid_data] = (uint8_t) ( ( raw_data & bitmask_offset(8,remainder) ) >> remainder );
            //fprintf(stderr, "%" PRIu8 " ", data[valid_data]);
            ++valid_data;
            if ( valid_data > expected_size ) {
              fprintf(stderr,"ERROR: http_random_producer: %s. Parsed %zu bytes of data where at most %zu bytes where expected.\n",http_random_source_names[source], valid_data, expected_size);
              break;
            }
            raw_data &= ~bitmask_offset(8,remainder);
            unprocessed_raw_data_length = remainder;
          }
          raw_data <<= RANDOMNUMBERS_INFO_BITS;
          token = endptr;
        }

        end += valid_data;
        *end = 0;

        if ( valid_data != expected_size ) {
          fprintf(stderr,"WARNING: http_random_producer: %s. Requested %zu bytes, got %zu bytes. Retrying.\n",http_random_source_names[source], expected_size, valid_data);
          ++zero_round;
          continue;
        }

        //fprintf(stderr, "\n%s\n", data);
        //fprintf(stdout, "%" PRIu8 "\t%" PRIu8 "\n", data[0], data[valid_data-1]);

      }
      //}}}    

      //{{{ Check for ERROR message in HOTBITS_RNG output
      if ( source == HOTBITS_RNG ) {
        if ( strstr( (char*) data, HOTBITS_ERR ) ) {
          fprintf(stderr, "ERROR: http_random_producer: %s. Site has returned following error message \"%s\".\n", http_random_source_names[source], HOTBITS_ERR);
          end = data;
          valid_data = 0;
          sleeptime = 24 * 3600;  //24hours. Please note that safe_sleep will reduce sleep time to end short after midnight UTC
          ++zero_round;
          continue;
        }
      }
      //}}}    

      //{{{ Check for ERROR message from RANDOM_ORG_RNG  
      if ( source == RANDOM_ORG_RNG ) {
        if ( strstr( (char*) data, RANDOM_ORG_ERR   ) ) {
          fprintf(stderr, "ERROR: http_random_producer: %s. Site has returned following error message \"%s\".\n", http_random_source_names[source], data);
          end = data;
          valid_data = 0;
          sleeptime = 24 * 3600;  //24hours. Please note that safe_sleep will reduce sleep time to end short after midnight UTC
          ++zero_round;
          continue;
        }
      }
      //}}}

      //{{{ Check for incomplete data
      if (  source == HOTBITS_RNG || source == RANDOM_ORG_RNG ) {
        //fprintf(stderr, "\n%s\n", data);
        //fprintf(stdout, "%" PRIu8 "\t%" PRIu8 "\n", data[0], data[valid_data-1]);
        if ( valid_data < size ) {
          fprintf(stderr,"WARNING: http_random_producer: %s. Requested %zu bytes, got %zu bytes.\n",http_random_source_names[source], size, valid_data);
          //TODO: we will not use incomplete data until local buffer FIPS validation is implemented
          ++zero_round;
          continue;
        }
      }
      //}}}

    }
    //}}}

    //{{{ Write data to the common buffer, perform FIPS testing 
    //TODO: add FIPS testing also on the local buffer to make sure that non-invalid data are mixed with valid data???   
    if ( valid_data == 0 ) continue;
    zero_round = 0;   //Reset zero_round counter

    data_added = 0;  //False - we will need to do FIPS validation first

    
    //fprintf(stderr, "http_random_producer:  %s waiting fox mux\n", http_random_source_names[source]);

    //Make sure that we will release the mutex when thread is cancelled.
    pthread_cleanup_push(mux_cleanup, (void *) &mutex);
    pthread_mutex_lock( &mutex );

    //fprintf(stderr, "http_random_producer:  got mutex\n");
    pthread_mutex_lock( &state_mutex );
    thread_running[source] = STATE_WAITING_FOR_BUFFER_TO_BE_EMPTY;
    pthread_cond_signal( &state_cond);
    pthread_mutex_unlock( &state_mutex);

    while (state->size - state->valid_data < valid_data) pthread_cond_wait( &empty, &mutex );

    pthread_mutex_lock( &state_mutex );
    thread_running[source] = STATE_RUNNING;
    pthread_cond_signal( &state_cond);
    pthread_mutex_unlock( &state_mutex);

    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    // 1. Rewind buffer
    if ( state->valid_data && state->buf_start !=  state->buf) {
      memmove( state->buf, state->buf_start, state->valid_data);
    }
    state->buf_start =  state->buf;

    //Fill buffer
    memcpy(state->buf_start + state->valid_data, data, valid_data);
    state->valid_data += valid_data;
    if ( verbosity > 1 ) fprintf(stderr, "http_random_producer: %s added %zu bytes, resulting in %zu available bytes in buffer from which %zu are FIPS validated\n", 
        http_random_source_names[source], valid_data, state->valid_data, state->fips_valided);
    state->data_added[source] += valid_data;

    //FIPS testing
    while ( state->valid_data - state->fips_valided >= FIPS_RNG_BUFFER_SIZE ) {
      ++state->fips_tests_executed[source] ;
      if ( fips_run_rng_test(&state->fips_ctx, state->buf_start + state->fips_valided) ) {
        //FIPS test has failed
        ++state->fips_fails[source];
        ++ state->fips_fails_in_row;
        if ( state->fips_fails_in_row > state->max_fips_fails_in_row ) state->max_fips_fails_in_row =  state->fips_fails_in_row;
        if ( verbosity > 1 ) fprintf(stderr, "http_random_producer: %s has rejectected %d bytes because of FIPS test failure, resulting in %zu available bytes in buffer from which %zu are FIPS validated\n", 
            http_random_source_names[source], FIPS_RNG_BUFFER_SIZE, state->valid_data, state->fips_valided);
        if ( state->fips_fails_in_row > 2 ) {
          if ( verbosity > 0 ) {
            fprintf(stderr, "ERROR: http_random_producer: %s. Allready %zu FIPS tests has failed in row. We will output FIPS tested data\n", http_random_source_names[source], state->fips_fails_in_row);
            rc = fwrite( state->buf_start + state->fips_valided, 1, FIPS_RNG_BUFFER_SIZE, stderr);
            if ( rc < FIPS_RNG_BUFFER_SIZE ) {
              fprintf(stderr, "ERROR: http_random_producer: %s. fwrite '%s' has failed - bytes written %d, bytes to write %d. Reported error: %s\n",
                  http_random_source_names[source], "stderr", rc, FIPS_RNG_BUFFER_SIZE, strerror(errno));
            }
          } else  {
            fprintf(stderr, "ERROR: http_random_producer: %s. Allready %zu FIPS tests has failed in row.\n",  http_random_source_names[source], state->fips_fails_in_row);
          }
        }

        if ( state->fips_valided == 0 ) {
          //We just need to move the beginning of the buffer
          state->buf_start += FIPS_RNG_BUFFER_SIZE;
          state->valid_data -= FIPS_RNG_BUFFER_SIZE;
        } else {
          //We have a hole in the data
          if ( state->valid_data - state->fips_valided - FIPS_RNG_BUFFER_SIZE > 0 ) {
            memcpy(state->buf_start + state->fips_valided, 
                state->buf_start + state->fips_valided + FIPS_RNG_BUFFER_SIZE, 
                state->valid_data - state->fips_valided - FIPS_RNG_BUFFER_SIZE);
          }
          state->valid_data -= FIPS_RNG_BUFFER_SIZE;
        }

      } else {
        //FIPS test has passed
        data_added = 1;
        state->fips_fails_in_row = 0;
        state->fips_valided += FIPS_RNG_BUFFER_SIZE;
        if ( verbosity > 1 ) fprintf(stderr, "http_random_producer: %s has FIPS validated block of data, resulting in %zu FIPS validated data in buffer\n", http_random_source_names[source], state->fips_valided);
      }
    }

    if ( data_added ) {
      pthread_cond_signal( &fill );
    }

    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

    pthread_mutex_unlock( &mutex );
    pthread_cleanup_pop(0);         /* Mutex has been released, cancel clenup handler execution */

    pthread_testcancel();           /* A cancellation point */
//}}}    
  }
//}}}

end_of_http_random_producer:
  if ( verbosity > 0 ) fprintf(stderr, "http_random_producer: %s ending thread\n", http_random_source_names[source]);
  pthread_cleanup_pop (1);
  if ( source == QRBG_RNG ) delete_name_and_password();
  return ( (void *) 0 );

}
//}}}

//{{{ http_random_state_t* http_random_init(char source, unsigned int size, char verbosity)
http_random_state_t* http_random_init(char source, size_t size, char verbosity, const char* QRBG_RNG_user_input,  const char* QRBG_RNG_passwd_input) {
  http_random_state_t* state;
  int rc;
  unsigned int last32=0;
  uint8_t i;

  assert(source < ipow(2,HTTP_COUNT) );
  assert(source>0);
  assert(size>=16384);               //Or at least FIPS_RNG_BUFFER_SIZE + 8192 = 2500 + 8192 = 10692 Bytes. 
                                     //Possible dead lock if buffer is smaller than FIPS_RNG_BUFFER_SIZE + MAX(local buffer size, over all producers)
  
  if ( init ) {
    fprintf(stderr, "ERROR: http_random_init: only one instance of http_random generator is allowed\n");
    return NULL;
  } else {
    init = 1;
  }


  if ( ( source & http_random_source_mask[QRBG_RNG] ) == http_random_source_mask[QRBG_RNG] ) {
    reset_string_with_mlock(&QRBG_RNG_user);
    reset_string_with_mlock(&QRBG_RNG_passwd);
    //Check if user & password has been provided for QRBG_RNG
    if ( QRBG_RNG_user_input == NULL || QRBG_RNG_passwd_input == NULL ) {
      fprintf(stderr, "ERROR: http_random_init: %s generator has been requested but either USERNAME and/or PASSWORD has not been provided. Disabling %s.\n", http_random_source_names[QRBG_RNG], http_random_source_names[QRBG_RNG]);
      source &= ~ http_random_source_mask[QRBG_RNG];     //Set http_random_source_mask[QRBG_RNG] bit to ZERO
    } else {
      //Copy username and password
      if ( copy_name_and_password( QRBG_RNG_user_input, QRBG_RNG_passwd_input) ) {
        fprintf(stderr, "ERROR: http_random_init: generator %s. Error while copying username and/or password. Disabling %s.\n", http_random_source_names[QRBG_RNG], http_random_source_names[QRBG_RNG]);
        source &= ~ http_random_source_mask[QRBG_RNG];     //Set http_random_source_mask[QRBG_RNG] bit to ZERO
      }
    }

    if ( source == 0 ) {
      fprintf(stderr, "ERROR: http_random_init: No other generator than %s has been specified, http_random_init has failed.\n", http_random_source_names[QRBG_RNG] );
      return NULL;
    }

  }



  pthread_mutex_lock( &state_mutex );
  for ( i=HOTBITS_RNG; i<HTTP_COUNT; ++i) {
    thread_running[i] = STATE_NOT_STARTED;
  }
  pthread_cond_signal( &state_cond);
  pthread_mutex_unlock( &state_mutex);


  state = (http_random_state_t*) calloc( 1, sizeof(http_random_state_t));
  if ( state ==NULL ) {
    fprintf(stderr, "ERROR: Dynamic memory allocation has failed for buffer of size %zu. Reported error: %s\n", sizeof(http_random_state_t), strerror(errno));
    return NULL;
  }

  state->buf	= (uint8_t*) calloc ( 1, size );
  if ( state->buf ==NULL ) {
    fprintf(stderr, "ERROR: Dynamic memory allocation has failed for buffer of size %zu. Reported error: %s\n", size, strerror(errno));
    return NULL;
  }

  for ( i=HOTBITS_RNG; i<HTTP_COUNT; ++i) {
    state->data_added[i] = 0;
    state->fips_tests_executed[i] = 0;
    state->fips_fails[i] = 0;
  }

  state->buf_start = state->buf;
  state->valid_data = 0;
  state->fips_valided = 0;
  state->fips_fails_in_row = 0;
  state->max_fips_fails_in_row = 0;
  state->size = size;
  state->source = source;
  state->verbosity = verbosity;
  fips_init( &state->fips_ctx, last32, 0);

  pthread_mutex_init( &mutex, NULL);
  pthread_mutex_init( &state_mutex, NULL);

  pthread_cond_init( &fill, NULL);
  pthread_cond_init( &empty, NULL);
  pthread_cond_init( &state_cond, NULL);

  for ( i=HOTBITS_RNG; i<HTTP_COUNT; ++i) {
    if ((source & http_random_source_mask[i]) == http_random_source_mask[i]) {
      input[i].source = i;
      input[i].state = state;

      rc = pthread_create(&thread[i], NULL, http_random_producer, (void *) &input[i]);
      if (rc){
        fprintf(stderr, "ERROR: return code from pthread_create() for %s is %d\n", http_random_source_names[i], rc);
      }
    }
  }


  return state;
}
//}}}

//{{{ unsigned int http_random_generate(http_random_state_t* state, uint8_t* output, unsigned int size, unsigned int max_timeout)
//TODO: POSIX threads does not stop pthread_cond_timedwait on interrupt. It will be restarted. Should we rewrite this routine without using pthread_cond_timedwait ??
//For one solution see http://fixunix.com/unix/257454-pthread_cond_timedwait-signal-handler.html
//See also pthread_sigmask, pthread_kill, sigwait - handling of signals in threads
//Simple solution: reset SIGINT, SIGTERM and SIGPIPE to the default action SIG_DFL to stop the program
unsigned int http_random_generate(http_random_state_t* state, uint8_t* output, size_t size, unsigned int max_timeout) {

  int rc;
  struct timespec   ts;
  char verbosity;
  struct sigaction sigact[4];

  pthread_mutex_lock( &mutex );
  verbosity = state->verbosity;

  sigemptyset( &sigact[0].sa_mask );
  sigact[0].sa_flags = 0;
  sigact[0].sa_handler = SIG_DFL;

  if ( sigaction(SIGINT,  &sigact[0], &sigact[1]) != 0 ) { fprintf(stderr, "ERROR: http_random_generate: sigaction has failed.\n"); }
  if ( sigaction(SIGTERM, &sigact[0], &sigact[2]) != 0 ) { fprintf(stderr, "ERROR: http_random_generate: sigaction has failed.\n"); }
  if ( sigaction(SIGPIPE, &sigact[0], &sigact[3]) != 0 ) { fprintf(stderr, "ERROR: http_random_generate: sigaction has failed.\n"); }

  while (state->fips_valided < size) {
    clock_gettime(CLOCK_REALTIME, &ts);

    ts.tv_sec += max_timeout;               //WAIT TIME IN SECONDS
    if ( verbosity > 1 ) fprintf(stderr,"http_random_generate: available FIPS validated %zu bytes. Bytes requested %zu. Waiting for max %u seconds.\n", 
        state->fips_valided, size, max_timeout);
    rc = pthread_cond_timedwait(&fill, &mutex, &ts);
    if (rc == ETIMEDOUT) {
      if ( verbosity > 1 ) fprintf(stderr, "http_random_generate: pthread_cond_timedwait timed out!\n");
      if ( verbosity > 1 ) fprintf(stderr, "http_random_generate: FIPS validated bytes available %zu, bytes requested %zu\n", state->fips_valided, size);
      size = state->fips_valided;
      if ( size > 0 ) {
        break;
      } else {
        fprintf(stderr, "ERROR: http_random_generate: No bytes currently available!\n");
        pthread_cond_signal(&empty);
        pthread_mutex_unlock(&mutex);
        return 0;
      }
    }
  }
  if ( sigaction(SIGINT,  &sigact[1], NULL) != 0 ) { fprintf(stderr, "ERROR: http_random_generate: sigaction has failed.\n"); }
  if ( sigaction(SIGTERM, &sigact[2], NULL) != 0 ) { fprintf(stderr, "ERROR: http_random_generate: sigaction has failed.\n"); }
  if ( sigaction(SIGPIPE, &sigact[3], NULL) != 0 ) { fprintf(stderr, "ERROR: http_random_generate: sigaction has failed.\n"); }

  if ( verbosity > 1 ) fprintf(stderr,"http_random_generate: producing %zu bytes\n", size);
  memcpy(output, state->buf_start, size);
  state->valid_data -= size;
  state->fips_valided -= size;
  state->buf_start += size;

  pthread_cond_signal(&empty);
  pthread_mutex_unlock(&mutex);

  return size;
}
//}}}

//{{{ unsigned int http_random_destroy(http_random_state_t* state)
unsigned int http_random_destroy(http_random_state_t* state) {
  int rc;
  //void *status;
  uint8_t i;
  uint8_t call_pthread_cancel;

  if ( ! init ) {
    fprintf(stderr, "ERROR: http_random_destroy: http_random_init has not been called\n");
    return 1;
  } else {
    init = 0;
  }
  for ( i=HOTBITS_RNG; i<HTTP_COUNT; ++i) {
    if ((state->source & http_random_source_mask[i]) == http_random_source_mask[i]) {
      if ( pthread_mutex_trylock ( &state_mutex ) ) {
        //Mutex is locked by another thread => call cancel without checking the status
        call_pthread_cancel = 1;
       } else {
        //We got mutex => can check the state
        if ( thread_running[i] == STATE_FINISHED ) {
          call_pthread_cancel = 0;
        } else {
          call_pthread_cancel = 1;
        }
        //Release mutex
        pthread_mutex_unlock( &state_mutex );
      }

      if ( call_pthread_cancel == 1 ) {
        if ( state->verbosity > 1 ) fprintf(stderr, "INFO: http_random_destroy: We will call pthread_cancel for thread %s\n",
            http_random_source_names[i]);
        rc = pthread_cancel(thread[i]);
        if (rc) {
          fprintf(stderr, "ERROR: http_random_destroy. Return code from pthread_cancel() for %s is %d\n", http_random_source_names[i], rc);
        }
      } else {
        if ( state->verbosity > 1 ) fprintf(stderr, "INFO: http_random_destroy: thread %s has already finished, we will call pthread_join\n",
            http_random_source_names[i]);
      }
      //rc = pthread_join(thread[i], &status);
      rc = pthread_join(thread[i], NULL);
      if (rc) {
        fprintf(stderr, "ERROR: http_random_destroy. Return code from pthread_join() for %s is %d\n", http_random_source_names[i], rc);
        continue; 
      }
      //fprintf(stderr,"http_random_destroy: completed join with %s suceeeded with status %ld\n", http_random_source_names[i],(long)status);
      }
  }


  rc = pthread_mutex_destroy( &mutex );
  if (rc) {
    fprintf(stderr, "ERROR: http_random_destroy. Return code from pthread_mutex_destroy() for \"mutex\" is %s\n", strerror(rc));
  }
  rc = pthread_mutex_destroy( &state_mutex );
  if (rc) {
    fprintf(stderr, "ERROR: http_random_destroy. Return code from pthread_mutex_destroy() for \"state_mutex\" is %s\n", strerror(rc));
  }

  rc = pthread_cond_destroy( &fill );
  if (rc) {
    fprintf(stderr, "ERROR: http_random_destroy. Return code from pthread_cond_destroy() for \"fill\" is %s\n", strerror(rc));
  }
  rc = pthread_cond_destroy( &empty );
  if (rc) {
    fprintf(stderr, "ERROR: http_random_destroy. Return code from pthread_cond_destroy() for \"empty\" is %s\n", strerror(rc));
  }
  rc = pthread_cond_destroy( &state_cond );
  if (rc) {
    fprintf(stderr, "ERROR: http_random_destroy. Return code from pthread_cond_destroy() for \"state_cond\" is %s\n", strerror(rc));
  }

  //QRBG_RNG_user & QRBG_RNG_passwd should be deleted already in this stage. Calling it again just to make sure that nothing went wrong during thread cancellation
  if ( ( state->source & http_random_source_mask[QRBG_RNG] ) == http_random_source_mask[QRBG_RNG] ) delete_name_and_password();

  free(state->buf);
  free(state);
  return 0;
}
//}}}

//{{{ unsigned int http_random_status(http_random_state_t* state)
//Returns number of active threads in state running of waiting for buffer to output the data
unsigned int http_random_status(http_random_state_t* state, char print) {
  uint8_t i;
  int status=0;
  char verbosity;
  char detailed_statistics;
 
  if ( print ) {
    verbosity = state->verbosity;
  } else {
    verbosity = 0;
  }

  if ( ! init ) {
    fprintf(stderr, "ERROR: http_random_status: http_random_init has not been called\n");
    status = -1;
    return status;
  }

  pthread_mutex_lock( &state_mutex );

  for ( i=HOTBITS_RNG; i<HTTP_COUNT; ++i) {
    detailed_statistics = 0;
    if ((state->source & http_random_source_mask[i]) == http_random_source_mask[i]) {
      switch (thread_running[i]) {
        case STATE_NOT_STARTED:
          if ( verbosity) fprintf(stderr, "INFO: thread %s has not been started yet.", http_random_source_names[i] );
          break;
        case STATE_RUNNING:
          if ( verbosity) fprintf(stderr, "INFO: thread %s is running.", http_random_source_names[i] );
          detailed_statistics = 1;
          ++status;
          break;
        case STATE_WAITING_FOR_BUFFER_TO_BE_EMPTY:
          if ( verbosity) fprintf(stderr, "INFO: thread %s is waiting for buffer to be empty.", http_random_source_names[i] );
          detailed_statistics = 1;
          ++status;
          break;
        case STATE_SLEEPING:
          if ( verbosity) fprintf(stderr, "INFO: thread %s is sleeping.", http_random_source_names[i] );
          detailed_statistics = 1;
          ++status;
          break;
        case STATE_FINISHED:
          if ( verbosity) fprintf(stderr, "INFO: thread %s has finished.", http_random_source_names[i] );
          detailed_statistics = 1;
          break;
        default:
          fprintf(stderr, "ERROR: thread %s: unknown state %d.", http_random_source_names[i], thread_running[i]  );
      }
      if ( detailed_statistics ) {
        if ( verbosity) fprintf(stderr, "It has produced %s bytes, has executed %"PRIu64" FIPS tests from which %"PRIu64" has failed.\n",
              human_print_int(state->data_added[i]), state->fips_tests_executed[i], state->fips_fails[i]);
      } else {
        if ( verbosity) fprintf(stderr, "\n");
      }
    } else {
      if ( verbosity) fprintf(stderr, "INFO: thread %s has been disabled on user request.\n", http_random_source_names[i] );

    }
  }

  if ( verbosity) {
    fprintf ( stderr, "============http_random_status: FIPS statistics for all threads==========\n");
    fprintf ( stderr, "%s", dump_fips_statistics ( &state->fips_ctx.fips_statistics ) );
  }

  if ( verbosity > 1 ) {
    fprintf ( stderr, "============http_random_status: state of the HTTP output buffer==========\n");
    fprintf ( stderr, "Total available bytes in the buffer: %zu\n", state->valid_data);
    fprintf ( stderr, "Total FIPS validated bytes in the buffer: %zu\n", state->fips_valided);
    fprintf ( stderr, "Latest FIPS check fails in row: %zu\n", state->fips_fails_in_row);
    fprintf ( stderr, "Maximum of FIPS check fails in row: %zu\n", state->max_fips_fails_in_row);
  }

  if ( verbosity) {
    fprintf ( stderr, "============http_random_status: end of report============================\n");
  }

  pthread_mutex_unlock( &state_mutex);

  return status;
}
//}}}

