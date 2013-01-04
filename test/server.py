#!/usr/bin/python                                                                                                                            
# -*- coding: utf-8 -*- 

# Copyright notice
# 
# Copyright (C) 2011-2013 Jirka Hladky <hladky DOT jiri AT gmail DOT com>
# 
# This file is part of CSRNG http://code.google.com/p/csrng/
# 
# CSRNG is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# CSRNG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with CSRNG.  If not, see <http://www.gnu.org/licenses/>.

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from urlparse import parse_qs
from time import sleep
from twisted.python.randbytes import *

class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        qs = {}
        path = self.path
        #print path
        if '?' in path:
            path, tmp = path.split('?', 1)
            qs = parse_qs(tmp)
        print path, qs
        self.wfile.write(path)
        value = int(qs.get('nbytes', ['0'])[0])
        print value
        #sleep(30)
        #for x in range(1,value+1):
        #    x %= 255
            #print x
        #    self.wfile.write(chr(x))
            #sleep(0.05)
        self.wfile.write(secureRandom(value))



if __name__ == "__main__":
    try:
        server = HTTPServer(('localhost', 8080), MyHandler)
        print('Started http server')
        server.serve_forever()
    except KeyboardInterrupt:
        print('^C received, shutting down server')
        server.socket.close()
