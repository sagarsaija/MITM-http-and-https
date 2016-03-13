import sys, os, threading, logging, argparse, urlparse, socket, SocketServer
import thread
from time import sleep
import Queue
import subprocess
import ssl
from subprocess import Popen, PIPE
#import openssl
#from OpenSSL import SSL

MAXCON = 10     # max connection queues to hold
MAXBUF = 4096   # buffer size
#port = 8080
#ssl_certfile = "/Users/sagarsaija/Desktop/lab3/ssl_certfile"
# logging.basicConfig(level=logging.INFO)
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
log = False

# exit codes
SUCCESS = 0     # operation successful
CONNFL = 1      # can't connect to server
AUTHFL = 2      # authentication failed
FLNFND = 3      # file not found
SYNERR = 4      # syntax error in client request
CMDNIMP = 5     # command not implemented by server
OPNALWD = 6     # operation not allowed by server
GENERR = 7      # generic error


class ProxyRequestHandler:

    def __init__(self, port, numworker, timeout):
        self.port = port
        self.numworker = numworker  #handle numworker with max and block
        self.timeout = timeout
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.thread_iterator = 0

        self.cakey = 'ca.key'
        self.cacert = 'ca.crt'
        self.certkey = 'cert.key'
        self.certdir = 'certs/'

    def run(self):
        #log_msg('Starting HTTP proxy server...', 'debug')
        try:
            self.server.bind(('', self.port))
            #log_msg('HTTP proxy server successfully binds to port %d' % self.port, 'debug')
            self.server.listen(MAXCON)
            #log_msg('HTTP proxy server listening on port %d' % self.port, 'debug')
        except socket.error, (value, message):
            if self.server:
                self.server.close()
                print "Could not open socket:", message
                sys.exit(1)
        while 1:
            try:
                conn, addr = self.server.accept()
                thread.start_new_thread(self.handle_proxy_request, (conn, addr))
            except KeyboardInterrupt:
                self.server.close()
                print "KeyboardInterrupt\n"
                exit_msg('Closing connection with server.', SUCCESS)
                #sys.exit(0)
        self.server.close()
    def handle_proxy_request(self, conn, addr):
        data = conn.recv(MAXBUF)
        #log_msg(data, 'info')
        hostname, port = None, None
        hostname, port = self.parse(hostname,port,data)
        #log_msg('port : %d' % port, 'debug')
        #log_msg('host : %s' % hostname, 'debug')
        #log_msg('addr : %d' % addr, 'debug')

        if port == 443:
            print "Connect to HTTPS:", hostname, port
            #self.handle_https(hostname,port,data)
            #another = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            #another.connect((addr,80)
            conn.send("HTTP/1.1 200 OK\r\n\r\n")
            hello = conn.recv(MAXBUF)
            #print "STRING: " + reply
            #get SNI, parse
            #SNI = self.parse_SNI(hello)
            #print "SNI\n"
            #print SNI
            #SNI = hostname
            #context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            #context.wrap_socket(downsock, do_handshake_on_connect=False, server_hostname=rhost)
            #proxy_key = open()
            #ssl_certfile = open('ssl_certfile','w')
            proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_socket.connect((unicode(hostname), port))
            IP = socket.gethostbyname(hostname)
            print "IP :" + IP
            #ssl_proxy_socket = ssl.wrap_socket(proxy_socket,ca_certs=ssl_certfile,server_side=False,cert_reqs=ssl.CERT_REQUIRED,ssl_version=ssl.PROTOCOL_TLSv1, ciphers="ADH-AES256-SHA",do_handshake_on_connect=True)
            #sslprotocols = ssl.PROTOCOL_SSLv3#ssl.PROTOCOL_TLSv1
            #sslcontext = ssl.SSLContext(sslprotocols)
            sslcontext = ssl.create_default_context()
            sslcontext.verify_mode = ssl.CERT_REQUIRED

            #ssl_proxy_socket = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            #ssl_proxy_socket = ssl.wrap_socket(proxy_socket)#,do_handshake_on_connect=False)
            ssl_proxy_socket = sslcontext.wrap_socket(proxy_socket,do_handshake_on_connect=True, server_hostname = hostname)#,server_side=False, do_handshake_on_connect=True)
            #ssl_proxy_socket.connect((unicode(SNI), port))
            #ssl_proxy_socket.do_handshake()
            #sslcontext.do_handshake()
            cert = ssl_proxy_socket.getpeercert()
            #cert = ssl_proxy_socket.get_server_certificate((unicode(SNI), port))
            print "hello"
            print cert
            ssl_proxy_socket.sendall(hello)
            ssl_proxy_socket.close()
            proxy_socket.close()
            #ssl_proxy_socket.
            #context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)

        else:
            print "Connect to HTTP:", hostname, port
            try:
                proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                proxy_socket.connect((unicode(hostname), port))
                proxy_socket.send(data)
                #send http request from proxy
                while 1:
                    reply = proxy_socket.recv(MAXBUF)
                    #log_msg(reply, 'info')
                    if (len(reply) > 0):
                        conn.send(reply)
                    else:
                        break
                proxy_socket.close()
                conn.close()
            except socket.error, (value, message):
                if proxy_socket:
                    proxy_socket.close()
                if conn:
                    conn.close()
                print "RUNTIME ERROR: ", message
                sys.exit(1)

        '''
        socket_file, counter = conn.makefile(),0
        out_lines, destination = [], None
        #print "4\n"
        hostname, port = None, None
        for l in socket_file.readlines():
            counter += 1
            out_lines.append(l)
            #if counter is 1:
            #    first_line_list = l.split(' ')#request
            #    if  first_line_list[0] in ('GET','ALIVE'):
            if counter is 2: #destination line
                print 'LINE '+l
                line_list = l.split(':')
                if len(line_list) is 3:
                    hostname, port = (l.split(':')[-2]).strip(), int(l.split(':')[-1])
                    print "hello"
                elif len(line_list) is 2:
                    hostname, port = line_list[-1].strip(), None
                    print "world"
                    if line_list[0] in ("LINE", "CONNECT"):
                        pass

                #print port
        #once we have data and destination
        #connect to server socket from hostname request
        try:
            proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if port is None:
                proxy_socket.connect((unicode(hostname), 80))
                print 'HOSTNAME: '+hostname
            else:
                proxy_socket.connect(((unicode(hostname), port)))

            proxy_socket_file =proxy_socket.makefile()
            a_string = ""
            #send http request from proxy
            for l in out_lines:
                proxy_socket.sendall(l)
                a_string += l
            print "a_string: "+ a_string
            k = ''
            #recieve
            for l in proxy_socket_file.readlines():
                k += l


            print "RETURNDATA: "+k
            #send it back to phone
            i = conn.sendall(k)
            print "NUMBER OF BYTES SENT TO PHONE:"
            print i
            proxy_socket_file.close()
            proxy_socket.close()
            socket_file.close()
        except socket.error, (value, message):
            if proxy_socket:
              proxy_socket.close()
            if conn:
              conn.close()
            print "Runtime Error:", message
            sys.exit(1)
        '''
    def parse(self, hostname, port, data):
        try:
            first_line = data.split('\n')[0]
            url = first_line.split(' ')[1]
            http_pos = url.find("://")
            if (http_pos==-1):
                temp = url
            else:
                temp = url[(http_pos+3):]
            port_pos = temp.find(":")
            hostname_pos = temp.find("/")
            if hostname_pos == -1:
                hostname_pos = len(temp)
            hostname = ""
            port = -1
            if (port_pos==-1 or hostname_pos < port_pos):
                port = 80
                hostname = temp[:hostname_pos]
            else:
                port = int((temp[(port_pos+1):])[:hostname_pos-port_pos-1])
                hostname = temp[:port_pos]
        except Exception, e:
            pass
        return hostname, port
        '''
        host = ''
        port = 0
        try:
            get = data.split('\n')[0].split()[1]
            if get.find('://') > 0:
                get = get[7:]

            portstart = get.find(':')
            hostend = get.find('/')

            if portstart < 0 or hostend < portstart:
                port = 80
                host = get[:hostend]
            else:
                port = int((get[(portstart + 1):])[:hostend - portstart - 1])
                host = get[:portstart]

        except Exception, e:
            pass

        return host, port
        '''
    def parse_SNI(self,hello):
        #print hello
        #h = unicode(hello)
        #print h
        #for l in hello:
        split_url = list(hello)
        ret_url = ""

        #i = 96
        #start_pt = split_url[i] + split_url[i+1] + split_url[i+2]
        #print "START"
        #print start_pt
        '''
        start_pt = split_url[i]
        while(ret_url[-1] != "\n"):
            ret_url += start_pt
            i = i + 1
            start_pt = split_url[i]
        '''
        '''
        while(start_pt != '.'):
            ret_url += start_pt
            i = i + 1
            start_pt = split_url[i]
        tmp_dom = ret_url[-3]+ret_url[-2]+ret_url[-1]
        print "TMP"
        print tmp_dom
        if tmp_dom not in ("com","net","edu","org"):
            while(start_pt != '.'):
                ret_url += start_pt
                i = i + 1
                start_pt = split_url[i]
        '''

        return ret_url
        #p = h[96]
        #c = h[97]
        #print "DAM MAMMA"
        #print p
        #print c

    def handle_https(self,hostname,port,data):
        print "CREATE CERTIFICATE"
        #keychain
        #keychain = Popen(["openssl", "req", "-new", "-key", self.certkey, "-subj", "/CN=%s" % hostname], stdout=PIPE)
        #print p1
        #certificate
        #certificate = Popen(["openssl", "x509", "-req", "-days", "3650", "-CA", self.cacert, "-CAkey", self.cakey, "-set_serial", epoch, "-out", certpath], stdin=p1.stdout, stderr=PIPE)
        #self.s.send("HTTP/1.1 200 OK\r\n\r\n")
        #reply = self.server.recv(MAXBUF)
        #print reply

# logs info message if logging is set to True, or logs msg as debug
def log_msg(msg, l_type):
    if log is True and l_type is 'info':
        logger.info(msg)
    else:
        logger.debug(msg)
# logs exit message and closes program with exit code
def exit_msg(msg, num):
    log_msg('Program exited with code : %d ( %s )' % (num, msg), 'debug')
    sys.exit(num)

if __name__ == '__main__':
    #global log
    numworker = 10
    timeout = -1
    parseargs = argparse.ArgumentParser()
    # parseargs.add_argument('-h', '--help',
    #                        action='store_true',
    #                        help='display usage information and exit')
    parseargs.add_argument('-v', '--version',
                           action='version', version=0.1,
                           help='print version and author information and exit')
    parseargs.add_argument('-p', '--port',
                           type=int, required=True,
                           help='specify port number server will be listening on')
    parseargs.add_argument('-n', '--numworker',
                           default=10, type=int,
                           help='specify number of workers in thread pool, default = 10')
    parseargs.add_argument('-t', '--timeout',
                           default=-1, type=int,
                           help='specify time to wait for server response, default = infinite ( -1 )')
    parseargs.add_argument('-l', '--log',
                           action='store_true',
                           help='specify whether to log request / response exchanges')
    args = parseargs.parse_args()

    if args.port > 65535 or args.port < 1:
        exit_msg('Invalid port number : %d' % args.port, SYNERR)
    elif args.numworker < 1 or args.numworker > 255:
        exit_msg('Invalid number of worker threads : %d' % args.numworker, SYNERR)

    if args.log is True:
        log = True
    proxy = ProxyRequestHandler(args.port, args.numworker, args.timeout)
    proxy.run()
