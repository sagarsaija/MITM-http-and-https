import sys, os, threading, logging, argparse, urlparse, socket, SocketServer
import thread
import time
import Queue
import subprocess
import ssl
from subprocess import Popen, PIPE, STDOUT
import subprocess
import io
import struct
import traceback
import OpenSSL
from OpenSSL import crypto
import random
import select
MAXCON = 10     # max connection queues to hold
MAXBUF = 4096   # buffer size
root_key = "/fs/student/sagarsaija/cs176b/hw3/github_hw3/ca.key"
#= os.path.join(os.path.dirname(__file__), 'ca.key')
root_cert = "/fs/student/sagarsaija/cs176b/hw3/github_hw3/ca.crt"
#= os.path.join(os.path.dirname(__file__), 'ca.cert')


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
        #super(ProxyRequestHandler, self).__init__()
        self.port = port
        self.numworker = numworker  #handle numworker with max and block
        self.sem_lock = threading.Semaphore(self.numworker)
        #self.workerQ = Queue.Queue()
        #self.masterQ = Queue.Queue()
        #self.counter = self.Counter()
        #self.active = []
        self.timeout = timeout
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #self.server.setblocking(0)
        self.thread_iterator = 0
        self.lock = threading.Lock()

    class Counter(object):
        def __init__(self, start=0):
            self.lock = threading.Lock()
            self.value = start
        def increment(self):
            logging.debug('Waiting for lock')
            self.lock.acquire()
            try:
                logging.debug('Acquired lock')
                self.value = self.value + 1
            finally:
                self.lock.release()
    def run(self):
        #log_msg('Starting HTTP proxy server...', 'debug')
        try:
            self.server.bind(('', self.port))
            #log_msg('HTTP proxy server successfully binds to port %d' % self.port, 'debug')
            self.server.listen(MAXCON)
            #self.sem_lock = threading.Semaphore(value = numworker)
            #log_msg('HTTP proxy server listening on port %d' % self.port, 'debug')
        except socket.error, (value, message):
            if self.server:
                self.server.close()
                print "Could not open socket:", message
                sys.exit(1)
        while 1:
            try:
                if self.timeout is not -1:
                    self.server.settimeout(self.timeout)
                conn, addr = self.server.accept()
                #conn.setblocking(0)
                #while(self.sem_lock > 0):
                #thread = threading.Thread(target=self.handle_proxy_request, args = (conn, addr))
                #thread.start()
                thread.start_new_thread(self.handle_proxy_request, (conn, addr))
                    #thread.start_new_thread(self.handle_proxy_request, (conn, addr))
                    #debug
                    #if(self.numworker == 10):
                        #thread.start_new_thread(self.handle_proxy_request, (conn, addr))
                    #else:
                        #self.start_pool_threads(self.numworker,conn,addr)
            except KeyboardInterrupt:
                #self.sem_lock.release()
                print "KeyboardInterrupt"
                self.server.close()
                #exit_msg('Closing connection with server.', SUCCESS)
                pid = os.getpid()
                cmd = "kill -9 " + str(pid)
                os.system(cmd)

        self.server.close()
    def handle_proxy_request(self, conn, addr):
        #self.sem_lock.acquire() #blocking = False
        #self.server.setblocking(0)
        #ready = select.select([self.server], [], [], self.timeout)
        #if ready[0]:
            #data = conn.recv(MAXBUF)
        #data = self.Recv(self.server)
        #log_msg(data, 'info')
        #print "hello"
        client_IP = addr[0]


        if self.timeout is not -1:
            conn.settimeout(self.timeout)
            data = conn.recv(MAXBUF)
            conn.settimeout(None)
        else:
            data = conn.recv(MAXBUF)
        hostname, port = None, None
        hostname, port = self.parse(hostname,port,data)
        #log_msg('port : %d' % port, 'debug')
        #log_msg('host : %s' % hostname, 'debug')
        #log_msg('addr : %d' % addr, 'debug')

        if hostname is None or port is None:
            pass

        elif port == 443:
            print "Connect to HTTPS:", hostname, port
            conn.send("HTTP/1.1 200 OK\r\n\r\n")
            if self.timeout is not -1:
                conn.settimeout(self.timeout)
                real_data = conn.recv(MAXBUF, socket.MSG_PEEK)
                conn.settimeout(None)
            else:
                real_data = conn.recv(MAXBUF, socket.MSG_PEEK)
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
            #rint "SNI: " #SNI
            #print SNI
            if SNI is None:
                SNI = hostname
            proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_socket.connect((unicode(hostname), port))
            IP = socket.gethostbyname(hostname)
            print "IP :" + IP

            real_context = ssl.create_default_context()
            real_context.verify_mode = ssl.CERT_REQUIRED

            real_proxy_socket = real_context.wrap_socket(proxy_socket,do_handshake_on_connect=True, server_hostname = SNI)#,server_side=False, do_handshake_on_connect=True)

            real_cert = real_proxy_socket.getpeercert()
            real_cipher = real_proxy_socket.cipher()
            #print real_cipher
            #fake_key = OpenSSL.crypto.PKey()#os.path.expanduser('~/ca.key')#root_key #OpenSSL.crypto.PKey()
            #fake_key.generate_key(OpenSSL.crypto.TYPE_RSA, 1028)
            #print "KEY"
            #print fake_key
            #fake_cert = real_cert
            CN = None
            AN = []
            CN_star = ""
            if real_cert["subject"][-1][0][0] == 'commonName':
                #print l[:2]
                CN_star = real_cert["subject"][-1][0][1]
                print "init:"
                print CN_star
                print CN_star[:2]
                if CN_star[:2] is "*.":
                    s_ll = len(CN_star)
                    CN_star = CN_star[2:s_ll]
                    print "MID: "
                    print CN_star
                #CN = real_cert["subject"][-1][0][1]
                CN = CN_star
                print "COMMONNAMEFOUND"+str(CN)
            else:
                CN = hostname
            if real_cert.has_key("subjectAltName"):
                for typ, val in real_cert["subjectAltName"]:
                    if typ == "DNS": #and val == hostname:
                        AN.append(val)
            #CN=www.google.com/subjectAltName=DNS.1=endpoint.com,DNS.2=zz.example.com'
            #print "CN :"
            #print CN
            #print "AN :"
            #print AN
            '''
            AN_tmp_list = []
            for i in AN:
                AN_tmp_list.append("DNS%s=" % i)
                #: %s" % i)
            AN_tmp_list = ", ".join(AN_tmp_list)
            '''
            AN_tmp_list = ""
            i = 1
            for l in AN:
                #if AN[-1:]:
                    #l = "DNS." + str(i) + "=" + l
                #else:
                '''
                print l[:2]
                if l[:2] is "*.":
                    ll = len(l)
                    l = l[2:ll]
                '''
                l = "DNS." + str(i) + "=" + l + ","
                AN_tmp_list += l
                i = i + 1
            AN_tmp_list = AN_tmp_list[:-1]
            #print "AN_tmp_list: "
            #print AN_tmp_list

            #print "CERT_NAME:"
            #print cert_name
            #"openssl", "genrsa", "1024"
            cert_name = SNI + ".crt"
            key_name = SNI + ".key"
            csr_name = SNI + ".csr"
            #openssl_key = "openssl genrsa 1024 -out certs/" + key_name #SNI + ".key 2048"
            openssl_key = "openssl genrsa -out certs/" + key_name + " 2048"
            key_status = subprocess.check_call(openssl_key, shell = True)
            #csr_gen = "openssl req -new -subj '/CN=" + common_name + "/subjectAltName=" + alt_names + "' -key certs/" + key_name + " -out certs/" + csr_name
            #openssl_csr = "openssl req -new -subj '/CN" + CN + "/subjectAltName=" + AN_tmp_list + "' -key certs/" + key_name + " -out certs/" + csr_name
            openssl_csr = "openssl req -new -subj '/CN=" + CN + "/subjectAltName=" + AN_tmp_list + "' -key certs/" + key_name + " -out certs/" + csr_name
            csr_status = subprocess.check_call(openssl_csr, shell = True)
            #crt_gen = "openssl x509 -req -days 365 -in certs/" + csr_name + " -CA mycert.crt -CAkey mycert.key -set_serial 0x12345 -out certs/" + cert_name
            openssl_crt = "openssl x509 -req -days 365 -in certs/" + csr_name + " -CA ca.crt -CAkey ca.key -set_serial 0x12345 -out certs/" + cert_name
            #openssl_crt = "openssl x509 req -in certs/" + csr_name + " -CA ca.crt -CAkey ca.key -CAcreateserial -out certs/" + cert_name + " -days 365"
            crt_status = subprocess.check_call(openssl_crt, shell = True)
            #openssl_crt = "openssl req -new -x509 -subj '/CN" + CN + "/subjectAltName=" + AN_tmp_list + "' -key ca.key -out certs/" + cert_name
            #ostatus = subprocess.check_call(openssl_crt, shell = True)
            cert_dir_name = "certs/" + cert_name

            key_dir_name = "certs/" + key_name
            #print "FAKE CERT PATH: "
            #print cert_dir_name
            fake_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH) #ssl.create_default_context() #ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            fake_context.load_cert_chain(certfile=cert_dir_name, keyfile=key_dir_name)#"ca.key")
            fake_context.verify_mode = ssl.CERT_OPTIONAL
            fake_proxy_socket = fake_context.wrap_socket(conn,server_side=True, do_handshake_on_connect=True)#, server_hostname = client_IP)#, certfile = "ca.crt", keyfile = "ca.key")#, keyfile=p1, certfile=fake_cert, do_handshake_on_connect=True)
            fake_cert = fake_proxy_socket.getpeercert()
            print "FAKE _CERT: "
            print fake_cert
            print "HELLO"

            real_proxy_socket.close()
            fake_proxy_socket.close()
            proxy_socket.close()
            conn.close()
            '''
            CN = None
            AN = []
            #print real_cert

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
            fake_key.generate_key(OpenSSL.crypto.TYPE_RSA, 1028)
            #fake_cert = real_cert
            fake_cert = OpenSSL.crypto.X509()
            #fake_cert.set_version("3L")
            fake_cert.set_pubkey(fake_key)
            fake_cert.get_subject().CN = CN
            #fake_cert.get_subject().AN = AN

            #load AN to fake_cert
            #if AN_tmp_list:
                #fake_cert.add_extensions([crypto.X509Extension("subjectAltName", False, ",".join(AN_tmp_list))])
            #print fake_cert
            fake_cert.sign(fake_key, 'sha1')
            #fake_cert.get_all().

            fake_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            fake_context.verify_mode = ssl.CERT_REQUIRED
            fake_proxy_socket = fake_context.wrap_socket(self.server, fake_cert,do_handshake_on_connect=True)#, keyfile=p1, certfile=fake_cert, do_handshake_on_connect=True)
            #pass cert from client with request
            '''
            #self.sem_lock.release()



        else:
            print "Connect to HTTP:", hostname, port
            try:
                proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                proxy_socket.connect((unicode(hostname), port))
                #proxy_socket.connect((hostname, port))
                proxy_socket.send(data)
                #send http request from proxy
                while 1:
                    if self.timeout is not -1:
                        proxy_socket.settimeout(self.timeout)
                        reply = proxy_socket.recv(MAXBUF)
                        proxy_socket.settimeout(None)
                    else:
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
            #self.sem_lock.release()
        #self.sem_lock.release()
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
