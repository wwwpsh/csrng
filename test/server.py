#!/usr/bin/python                                                                                                                            
# -*- coding: utf-8 -*- 

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
