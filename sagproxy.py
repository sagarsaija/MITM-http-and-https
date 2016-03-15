import sys, os, threading, logging, argparse, urlparse, socket, SocketServer
import thread
import time
import Queue
import subprocess
import ssl
from subprocess import Popen, PIPE, STDOUT
import io
import struct
import traceback
import OpenSSL
from OpenSSL import crypto

MAXCON = 10     # max connection queues to hold
MAXBUF = 4096   # buffer size
root_key = "./ca.key"
root_crt = "./ca.crt"

'''
#create key
key = open("ca.key","w")
my_key = Popen(["openssl", "genrsa", "1024"], stdout = PIPE)#, stdout = PIPE)#, "-new", "-key", f_key, "-subj", "/CN=%s" % tt], stdout=PIPE)
for line in my_key.stdout:
    key.write(line)
key.close()
#create root certificate
certificate = open("ca.crt","w")
my_cert = Popen("openssl req -new -x509 -days 3650 -key ca.key -out ca.crt".split(), stdout=PIPE)
#my_cert = p_enc.communicate()[0]
#my_cert = Popen(["openssl", "x509", "-req", "-days", "365", "-signkey", my_key], stdout=PIPE)
for line in my_cert.stdout:
    certificate.write(line)
certificate.close()
'''
#gundo = socket.gethostbyname("www.yahoo.com")
#print "CHIEF"
#print gundo
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
        self.workerQ = Queue.Queue()
        self.masterQ = Queue.Queue()

        self.Pool = []
        self.timeout = timeout
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.thread_iterator = 0
        self.f_lock = threading.Lock()
        self.cakey = 'ca.key'
        self.cacert = 'ca.crt'
        self.certkey = 'cert.key'
        self.certdir = 'junk/'

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
                #thread.start_new_thread(self.handle_proxy_request, (conn, addr))
                #debug
                if(self.numworker == 10):
                    thread.start_new_thread(self.handle_proxy_request, (conn, addr))
                else:
                    self.start_pool_threads(self.numworker,conn,addr)
            except KeyboardInterrupt:
                self.server.close()
                print "KeyboardInterrupt\n"
                exit_msg('Closing connection with server.', SUCCESS)
                #sys.exit(0)
        self.server.close()
    #thread Pooling
    def start_pool_threads(self, numworker, conn, addr):
        for i in range(numworker):
            threadQ = threading.Thread(target=self.process_queue, args = (conn, addr))
            threadQ.start()
            self.Pool.append(threadQ)
    def process_queue(self,conn,addr):
        thread.start_new_thread(self.handle_proxy_request, (conn, addr))
        print "start_new_thread"
        flag = 'ok'
        while flag != 'stop':
            try:
                flag,item=self.masterQ.get()
                if flag=='ok':
                    print "start_flag"
                    newdata=item
                    self.workerQ.put(newdata)
            except:
                self.errorQ.put(err_msg())
    def err_msg(self):
        trace= sys.exc_info()[2]
        try:
            exc_value=str(sys.exc_value)
        except:
            exc_value=''
        return str(traceback.format_tb(trace)),str(sys.exc_type),exc_value
    def get_errors(self):
        try:
            while 1:
                yield errorQ.get_nowait()
        except Queue.Empty:
            pass
    def get(self):
        return self.workerQ.get()
    def put(self,data,flag='ok'):
        self.masterQ.put([flag,data])
    def get_all(self):
        try:
            while 1:
                yield self.workerQ.get_nowait()
        except Queue.Empty:
            pass
    def stop_threads(self):
        for i in range(len(self.Pool)):
            self.masterQ.put(('stop',None))
        while self.Pool:
            time.sleep(1)
            for index,the_thread in enumerate(self.Pool):
                if the_thread.isAlive():
                    continue
                else:
                    del self.Pool[index]
                break

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
            conn.send("HTTP/1.1 200 OK\r\n\r\n")
            real_data = conn.recv(MAXBUF)
            SNI = None
            if real_data.startswith('\x16\x03'):
                stream = io.BytesIO(real_data)
                stream.read(0x2b)
                session_id_length = ord(stream.read(1))
                stream.read(session_id_length)
                cipher_suites_length, = struct.unpack('>h', stream.read(2))
                stream.read(cipher_suites_length+2)
                extensions_length, = struct.unpack('>h', stream.read(2))
                while True:
                    data = stream.read(2)
                    if not data:
                        break
                    etype, = struct.unpack('>h', data)
                    elen, = struct.unpack('>h', stream.read(2))
                    edata = stream.read(elen)
                    if etype == 0:
                        server_name = edata[5:]
                        SNI = server_name
            print "SNI: " #SNI
            print SNI
            if SNI is None:
                SNI = hostname
            proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_socket.connect((unicode(hostname), port))
            IP = socket.gethostbyname(hostname)
            print "IP :" + IP

            real_context = ssl.create_default_context()
            real_context.verify_mode = ssl.CERT_REQUIRED

            real_proxy_socket = real_context.wrap_socket(proxy_socket,do_handshake_on_connect=True, server_hostname = hostname)#,server_side=False, do_handshake_on_connect=True)

            real_cert = real_proxy_socket.getpeercert()
            #print real_cert
            CN = None
            AN = []
            if real_cert["subject"][-1][0][0] == 'commonName':
                CN = real_cert["subject"][-1][0][1]
                print "COMMONNAMEFOUND"+str(CN)
            else:
                CN = hostname
            if real_cert.has_key("subjectAltName"):
                for typ, val in real_cert["subjectAltName"]:
                    if typ == "DNS": #and val == hostname:
                        AN.append(val)

            #print "CN :"
            #print CN
            #print "AN :"
            #print AN
            AN_tmp_list = []
            for i in AN:
                AN_tmp_list.append("DNS: %s" % i)
            AN_tmp_list = ", ".join(AN_tmp_list)
            #print "AN_tmp_list"
            #print AN_tmp_list
            #debug generate fake cert using CN, AN, and SNI
            fake_key = OpenSSL.crypto.PKey()#os.path.expanduser('~/ca.key')#root_key #OpenSSL.crypto.PKey()
            #print "NIGGER"
            #print root_key
            fake_key.generate_key(OpenSSL.crypto.TYPE_RSA, 1028)
            #fake_cert = real_cert
            fake_cert = OpenSSL.crypto.X509()
            #fake_cert.set_version("3L")
            fake_cert.set_pubkey(fake_key)
            fake_cert.get_subject().CN = CN
            #fake_cert.get_subject().AN = AN
            #if AN_tmp_list:
                #fake_cert.add_extensions([crypto.X509Extension("subjectAltName", False, ",".join(AN_tmp_list))])
            #
            #print "NIGGER"
            #print fake_cert
            fake_cert.sign(fake_key, 'sha1')
            #fake_cert.get_all().
            #print "NIGGER"
            #print type(lala)

            fake_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            fake_context.verify_mode = ssl.CERT_REQUIRED
            fake_proxy_socket = fake_context.wrap_socket(self.server, fake_cert,do_handshake_on_connect=True)#, keyfile=p1, certfile=fake_cert, do_handshake_on_connect=True)
            #pass cert from client with request

            real_proxy_socket.close()
            fake_proxy_socket.close()
            proxy_socket.close()
            conn.close()

        else:
            print "Connect to HTTP:", hostname, port
            try:
                proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                proxy_socket.connect((unicode(hostname), port))
                #proxy_socket.connect((hostname, port))
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
