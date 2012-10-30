/* vim: set expandtab cindent fdm=marker ts=2 sw=2: */

/* C interface for src/QRBG.h */

/* {{{ Copyright notice
Copyright (C) 2011, 2012 Jirka Hladky

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

#include <inttypes.h>
#include <stdio.h>
#include "QRBG.h"
//#define CUSTOM_QRBG_REPORTING
//TODO: make AUTH_FAILED and CC_QUOTA_EXCEEDED_PER_EON FATAL ERROR?

extern "C" {

#ifdef CUSTOM_QRBG_REPORTING
  static const char* QRBG_ServerResponseCodesName (QRBG::ServerResponseCodes d) {
    switch(d) {
      case QRBG::OK:                 return "OK: everything is ok (user found, quota not exceeded), sending data";
      case QRBG::SERVER_STOPPING:    return "SERVER_STOPPING: server is stopping (or at least it's shutting down this connection!)";
      case QRBG::SERVER_ERROR:       return "SERVER_ERROR: internal server error";
      case QRBG::UNKNOWN_OP:         return "UNKNOWN_OP: client requested unknown/unsupported operation";
      case QRBG::ILL_FORMED_REQUEST: return "ILL_FORMED_REQUEST: client sent an ill-formed request packet";
      case QRBG::TIMEOUT:            return "TIMEOUT: timeout while receiving the request from client";
      case QRBG::AUTH_FAILED:        return "AUTH_FAILED: user could not be authenticated - see enum RefusalReasonCodes";
      case QRBG::QUOTA_EXCEEDED:     return "QUOTA_EXCEEDED: user quota is (or would be exceeded) - see enum RefusalReasonCodes";
      default:                       return "ServerResponseCodes: unknown value";
    }
  };

  static const char* QRBG_RefusalReasonCodesName (QRBG::RefusalReasonCodes d) {
    switch(d) {
      case QRBG::NONE: return "NONE";
      case QRBG::BYTE_QUOTA_EXCEEDED_FOR_SESSION:       return "BYTE_QUOTA_EXCEEDED_FOR_SESSION: requested to much data in one session";
      case QRBG::BYTE_QUOTA_WOULD_EXCEED_FOR_EON:       return "BYTE_QUOTA_WOULD_EXCEED_FOR_EON: by serving this request, eon quota would be exceeded (request less data)";
      case QRBG::BYTE_QUOTA_EXCEEDED_FOR_EON:           return "BYTE_QUOTA_EXCEEDED_FOR_EON: eon quota is already exceeded";
      case QRBG::BYTE_QUOTA_WOULD_EXCEED_FOR_YEAR:      return "BYTE_QUOTA_WOULD_EXCEED_FOR_YEAR: by serving this request, yearly quota would be exceeded (request less data)";
      case QRBG::BYTE_QUOTA_EXCEEDED_FOR_YEAR:          return "BYTE_QUOTA_EXCEEDED_FOR_YEAR: yearly quota is already exceeded";
      case QRBG::BYTE_QUOTA_WOULD_EXCEED_FOR_MONTH:     return "BYTE_QUOTA_WOULD_EXCEED_FOR_MONTH: by serving this request, monthly quota would be exceeded (request less data)";
      case QRBG::BYTE_QUOTA_EXCEEDED_FOR_MONTH:         return "BYTE_QUOTA_EXCEEDED_FOR_MONTH: monthly quota is already exceeded";
      case QRBG::BYTE_QUOTA_WOULD_EXCEED_FOR_DAY:       return "BYTE_QUOTA_WOULD_EXCEED_FOR_DAY: by serving this request, daily quota would be exceeded (request less data)";
      case QRBG::BYTE_QUOTA_EXCEEDED_FOR_DAY:           return "BYTE_QUOTA_EXCEEDED_FOR_DAY: daily quota is already exceeded";
      case QRBG::CONCURRENT_CONNECTIONS_QUOTA_EXCEEDED: return "CONCURRENT_CONNECTIONS_QUOTA_EXCEEDED: maximum number of allowed parallel requests for authenticated user is already being served (wait and try again)";
      case QRBG::CC_QUOTA_EXCEEDED_PER_MINUTE:          return "CC_QUOTA_EXCEEDED_PER_MINUTE: user connections-per-minute limit exceeded (wait and try again)";
      case QRBG::CC_QUOTA_EXCEEDED_PER_HOUR:            return "CC_QUOTA_EXCEEDED_PER_HOUR: user connections-per-hour limit exceeded (wait and try again)";
      case QRBG::CC_QUOTA_EXCEEDED_PER_DAY:             return "CC_QUOTA_EXCEEDED_PER_DAY: user connections-per-day limit exceeded (wait and try again)";
      case QRBG::CC_QUOTA_EXCEEDED_PER_MONTH:           return "CC_QUOTA_EXCEEDED_PER_MONTH: user connections-per-month limit exceeded (wait and try again)";
      case QRBG::CC_QUOTA_EXCEEDED_PER_YEAR:            return "CC_QUOTA_EXCEEDED_PER_YEAR: user connections-per-year limit exceeded (wait and try again)";
      case QRBG::CC_QUOTA_EXCEEDED_PER_EON:             return "CC_QUOTA_EXCEEDED_PER_EON: user connections-per-eon limit exceeded (that's all folks!) ";
      default:                                          return "RefusalReasonCodes: unknown value";
    }
  };
#endif



  QRBG* newQRBG() {
    QRBG* p;
    try {
      p = new QRBG();
    } catch (QRBG::NetworkSubsystemError) {
      fprintf(stderr, "ERROR: newQRBG: Network error!\n");
      return NULL;
    } catch (...) {
      fprintf(stderr, "ERROR: newQRBG: Failure.\n");
      return NULL;
    }
    return p;
  }

  void deleteQRBG(QRBG *p) {
    delete p;
  }

  int defineServerQRBG(QRBG *p, const char* qrbgServerAddress, unsigned int qrbgServerPort) {
    try {
      p->defineServer(qrbgServerAddress, qrbgServerPort);
    } catch (QRBG::InvalidArgumentError e) {
      fprintf(stderr, "ERROR: defineServerQRBG: Invalid argument\n");
      return 1;
    } catch (...) {
      fprintf(stderr, "ERROR: defineServerQRBG: Failure.\n");
      return 1;
    }
    return 0;
  }

  int defineUserQRBG(QRBG *p, const char* qrbgUsername, const char* qrbgPassword) {
    try {
      p->defineUser(qrbgUsername, qrbgPassword);
    } catch (QRBG::InvalidArgumentError e) {
      fprintf(stderr, "ERROR: defineUserQRBG: Invalid argument\n");
      return 1;
    } catch (...) {
      fprintf(stderr, "ERROR: defineUserQRBG: Failure.\n");
      return 1;
    }
    return 0;
  }

  int getIntQRBG(QRBG *p, int* value) {
    int i;
    try {
      i = p->getInt();
    } catch (QRBG::ConnectError e) {
      fprintf(stderr, "ERROR: getIntQRBG: Network connection error.\n");
      return 1;
    } catch (QRBG::CommunicationError e) {
      fprintf(stderr, "ERROR: getIntQRBG: Communication error.\n");
      return 2;
    } catch (QRBG::ServiceDenied e) {
#ifdef CUSTOM_QRBG_REPORTING
      fprintf(stderr, "ERROR: getIntQRBG: Service denied! --> %s!\n", QRBG_ServerResponseCodesName(e.ServerResponse) );
      if ( e.ServerResponse == QRBG::AUTH_FAILED ||  e.ServerResponse == QRBG::QUOTA_EXCEEDED ) {
        fprintf(stderr, "ERROR: getIntQRBG: Reason: %s!\n", QRBG_ServerResponseCodesName(e.ServerResponse) );
      }
      fprintf(stderr, "ERROR: getIntQRBG: Explanation: %s\n", e.why()  );
      fprintf(stderr, "ERROR: getIntQRBG: What to do: %s\n", e.cure() );
#else
      fprintf(stderr, "ERROR: getIntQRBG: Service denied! --> %s! (%s.) \n", e.why(), e.cure());
#endif

      return 3;
    }

    *value = i;
    return 0;            //OK
  }

  size_t getIntsQRBG(QRBG *p, int* buffer, size_t count) {
    size_t i;
    try {
      i = p->getInts(buffer, count);
    } catch (QRBG::ConnectError e) {
      fprintf(stderr, "ERROR: getIntsQRBG: Network connection error.\n");
      //return 0;
    } catch (QRBG::CommunicationError e) {
      fprintf(stderr, "ERROR: getIntsQRBG: Communication error.\n");
      //return 0;
    } catch (QRBG::ServiceDenied e) {
#ifdef CUSTOM_QRBG_REPORTING
      fprintf(stderr, "ERROR: getIntsQRBG: Service denied! --> %s!\n", QRBG_ServerResponseCodesName(e.ServerResponse) );
      if ( e.ServerResponse == QRBG::AUTH_FAILED ||  e.ServerResponse == QRBG::QUOTA_EXCEEDED ) {
        fprintf(stderr, "ERROR: getIntsQRBG: Reason %s!\n", QRBG_ServerResponseCodesName(e.ServerResponse) );
      }
      fprintf(stderr, "ERROR: getIntsQRBG: Explanation %s\n", e.why()  );
      fprintf(stderr, "ERROR: getIntsQRBG: What to do: %s\n", e.cure() );
#else
      fprintf(stderr, "ERROR: getIntsQRBG: Service denied! --> %s! (%s.) \n", e.why(), e.cure());
#endif
      //return 0;
    }
    return i;           //Number of returned ints
  }

  int getByteQRBG(QRBG *p, uint8_t* value) {
    uint8_t i;
    try {
      i = (uint8_t) p->getByte();
    } catch (QRBG::ConnectError e) {
      fprintf(stderr, "ERROR: getByteQRBG: Network connection error.\n");
      return 1;
    } catch (QRBG::CommunicationError e) {
      fprintf(stderr, "ERROR: getByteQRBG: Communication error.\n");
      return 2;
    } catch (QRBG::ServiceDenied e) {
#ifdef CUSTOM_QRBG_REPORTING
      fprintf(stderr, "ERROR: getByteQRBG: Service denied! --> %s!\n", QRBG_ServerResponseCodesName(e.ServerResponse) );
      if ( e.ServerResponse == QRBG::AUTH_FAILED ||  e.ServerResponse == QRBG::QUOTA_EXCEEDED ) {
        fprintf(stderr, "ERROR: getByteQRBG: Reason %s!\n", QRBG_ServerResponseCodesName(e.ServerResponse) );
      }
      fprintf(stderr, "ERROR: getByteQRBG: Explanation %s\n", e.why()  );
      fprintf(stderr, "ERROR: getByteQRBG: What to do: %s\n", e.cure() );
#else
      fprintf(stderr, "ERROR: getByteQRBG: Service denied! --> %s! (%s.) \n", e.why(), e.cure());
#endif
      return 3;
    }
    *value = i;
    return 0;            //OK
  }

  size_t getBytesQRBG(QRBG *p, uint8_t* buffer, size_t count) {
    size_t i;
    try {
      i = p->getBytes(buffer, count);
    } catch (QRBG::ConnectError e) {
      fprintf(stderr, "ERROR: getBytesQRBG: Network connection error.\n");
      //return 0;
    } catch (QRBG::CommunicationError e) {
      fprintf(stderr, "ERROR: getBytesQRBG: Communication error.\n");
      //return 0;
    } catch (QRBG::ServiceDenied e) {
#ifdef CUSTOM_QRBG_REPORTING
      fprintf(stderr, "ERROR: getBytesQRBG: Service denied! --> %s!\n", QRBG_ServerResponseCodesName(e.ServerResponse) );
      if ( e.ServerResponse == QRBG::AUTH_FAILED ||  e.ServerResponse == QRBG::QUOTA_EXCEEDED ) {
        fprintf(stderr, "ERROR: getBytesQRBG: Reason %s!\n", QRBG_ServerResponseCodesName(e.ServerResponse) );
      }
      fprintf(stderr, "ERROR: getBytesQRBG: Explanation %s\n", e.why()  );
      fprintf(stderr, "ERROR: getBytesQRBG: What to do: %s\n", e.cure() );
#else
      fprintf(stderr, "ERROR: getBytesQRBG: Service denied! --> %s! (%s.) \n", e.why(), e.cure());
#endif
      //return 0;
    }
    return i;           //Number of returned ints
  }

}


