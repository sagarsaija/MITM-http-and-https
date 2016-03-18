import sys
import os
import threading
import argparse
import socket
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
import shutil
global log
global req_cnt
log = False
req_cnt = 1

MAXBUF = 4000  # buffer size
MAXCON = 10     # max connection queues to hold
#PUT THE LINES IN THE STRING IN A FILE CALLED temp.conf
OPENSSL_CONFIG_TEMPLATE = """
prompt = no
distinguished_name = req_distinguished_name
req_extensions = v3_req
[ req_distinguished_name ]
C                      = US
ST                     = CA
L                      = Goleta
O                      = Ghandi Inc.
OU                     = Domain India
CN                     =
emailAddress           = sagarsaija@yahoo.com
[ v3_req ]
# Extensions to add to a certificate request
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
[ alt_names ]
"""
#GENERATION OF KEYS, CERT REQTs, AND CERTS
#EITHER UNCOMMENT THESE OPENSSL LINES BELOW OR TYPE THEM ON THE TERMINAL
'''
root_key_cmd = "openssl genrsa -out ca.key 1024"
crt_root_key = subprocess.check_call(root_key_cmd, shell = True)
root_cert_cmd = "openssl req -x509 -new -nodes -key ca.key -days 3650 -out ca.pem"
crt_root_cert = subprocess.check_call(root_cert_cmd, shell = True)

#different
root_cert_cmd = "openssl req -x509 -nodes -days 365 -newkey rsa:4096 -keyout keys/ca.key -out certs/ca.crt -reqexts v3_req -extensions v3_ca"
crt_root_cert = subprocess.check_call(root_cert_cmd, shell = True)
'''

#ANDRIOD HARDCODE CONVERT
#root_der_cert_cmd = "openssl x509 -in certs/ca.pem -outform der -out certs/ca.der.crt"
#crt_root_cert = subprocess.check_call(root_der_cert_cmd, shell = True)
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


class ProxyRequestHandler:
    #init
    def __init__(self, port, log, numworker, timeout):
        #super(ProxyRequestHandler, self).__init__()
        self.port = port
	#loggging is activated
        if log:
            self.log = log
        self.numworker = numworker  #handle numworker with max and block
        self.sem_lock = threading.Semaphore(self.numworker) #SEMAPHORE IMPLEMENTATION OF THREAD POOL
        self.timeout = timeout #SET THE TIMEOUT VALUE FROM ARGS

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #SETUP OF CLIENT SOCKET
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        #self.wr_lock = threading.Semaphore(1)

        #self.req_cnt = 1
        #self.rep_cnt = 1
        #self.req_log = '1'
        #self.ip_log = ''
        #self.host_log = ''
        #self.name_log = ""

    #write to log for each request
    def wr_append_log(self, client_IP, hostname, data, flag):
        #self.wr_lock.acquire()
        req_log = '1' #str(self.req_cnt)
        log_cnt = 1
        name_log = req_log + '_' + client_IP + '_www.' + hostname
        log_path = self.log + '/' + name_log
        log_file = None
        #new first request
        if not os.path.isfile(log_path): #and flag is False:
            log_file = open(log_path, 'w')
            log_file.write(data)
            #self.req_cnt += self.req_cnt
        else:
            while (os.path.isfile(log_path)):
                log_cnt += log_cnt
                req_log = str(log_cnt)
                name_log = req_log + '_' + client_IP + '_www.' + hostname
                log_path = self.log + '/' + name_log
            log_file = open(log_path, 'a')
            log_file.write(data)
        log_file.close()

    #FOR EVERY REQUEST, WRITE ONE RESPONSE TO THE LOG
    def end_wr_append_log(self, client_IP, hostname, data, flag):
        log_cnt = 1
        req_log = '1'
        name_log = req_log + '_' + client_IP + '_www.' + hostname
        log_path = self.log + '/' + name_log
        #log_file = None
        log_file = open(log_path, 'a')
        #log_file.write(data)
        while (os.path.isfile(log_path)):
            log_cnt += log_cnt
            req_log = str(log_cnt)
            name_log = req_log + '_' + client_IP + '_www.' + hostname
            log_path = self.log + '/' + name_log
        #log_file = open(log_path, 'a')
        #log_file.write(data)
        if not os.path.isfile(log_path):
            #print "\n\nPASSED\n\n "
            tmp = name_log.split('_')
            tmp_int = int(tmp[0]) - 1 #tmp[0]
            tmp_log = str(tmp_int)
            tmp_log = tmp_log + '_' + client_IP + '_www.' + hostname
            tmp_path = self.log + '/' + tmp_log
            log_file = open(tmp_path, 'a')
            log_file.write(data)

        else:
            #print "\n\nFAILED!\n\n "
            pass
        log_file.close()
        #self.wr_lock.acquire()

    #RUN THE SERVER FOREVER
    def run(self):
        try:
            self.server.bind(('', self.port))
            self.server.listen(MAXCON)
        except socket.error, (value, message):
            if self.server:
                self.server.close()
                print "Could not open socket:", message
                sys.exit(1)
        while True:
            try:
                if self.timeout is not -1:
                    self.server.settimeout(self.timeout)
                conn, addr = self.server.accept()
                thread.start_new_thread(self.handle_proxy_request, (conn, addr))
            except KeyboardInterrupt:
                print "KeyboardInterrupt"
                self.server.close()
                pid = os.getpid()
                cmd = "kill -9 " + str(pid)
                os.system(cmd)

        self.server.close()

    #HANDLE EACH HTTP/HTTPS REQUEST
    def handle_proxy_request(self, conn, addr):
        #UNCOMMENT FOR NO DEFAULT THREADPOOL
        #if self.numworker is not 10:
        self.sem_lock.acquire()
        client_IP = addr[0]

        if self.timeout is not -1:
            try:
		conn.settimeout(self.timeout)
            	data = conn.recv(MAXBUF)
            	conn.settimeout(None)
	    except socket.timeout as to:
		print "WARNING: socket.timeout : timed out"
		raise to
        else:
            data = conn.recv(MAXBUF)
	#EXTRACT FIRST LINE OF DATA FOR HOSTNAME AND PORT FROM REQUEST
	#GET HTTP://example.com/ (port) HTTP/1.1
        hostname, port = None, None
	try:
            extract_line_one = data.split('\n')[0]
            extract_url = extract_line_one.split(' ')[1]
            extract_protocol = extract_url.find("://")
            if extract_protocol is not -1:
                counter = extract_url[(extract_protocol+3):]
            else:
                counter = extract_url
            extract_port = counter.find(":")
            extract_hostname = counter.find("/")
            if extract_hostname is -1:
                extract_hostname = len(counter)
            port = -1
	    hostname = ""
            if extract_hostname < extract_port or extract_port==-1:
		hostname = counter[:extract_hostname]
		#default port 80 for HTTP
		port = 80
            else:
                hostname = counter[:extract_port]
	        port = int((counter[(extract_port+1):])[:extract_hostname-extract_port-1])
        except Exception, e:
            pass
        if log:
            #self.wr_lock.acquire()
            flag = False
            self.wr_append_log(client_IP, hostname, data, flag)

	#BAD REQUEST
        if hostname is None or port is None:
	    print "WARNING: Hostname or Port not available"
            pass

	#PROCESS HTTPS REQUEST
        elif port == 443:
            print "Connect to HTTPS:", hostname, port
            IP = socket.gethostbyname(hostname)
            print "IP :" + IP
            conn.send("HTTP/1.1 200 OK\r\n\r\n")
            real_data = ""
            if self.timeout is not -1:
                conn.settimeout(self.timeout)
                real_data = conn.recv(MAXBUF, socket.MSG_PEEK)
                conn.settimeout(None)
            else:
                real_data = conn.recv(MAXBUF, socket.MSG_PEEK)
                #print real_data
            #if self.log:
                #flag = True
                #self.wr_append_log(client_IP, hostname, real_data, flag)

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
            #print "SNI: " #SNI
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
                CN = real_cert["subject"][-1][0][1]
                #print "COMMONNAMEFOUND"+str(CN)
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
            AN_tmp_list = ""
            i = 1
            for l in AN:
                l = "DNS." + str(i) + "=" + l + ","
                AN_tmp_list += l
                i = i + 1
            AN_tmp_list = AN_tmp_list[:-1]
            #print "AN_tmp_list: "
            #print AN_tmp_list

            #print "CERT_NAME:"
            #print cert_name
            #"openssl", "genrsa", "1024"

            #openssl_key = "openssl genrsa 1024 -out certs/" + key_name #SNI + ".key 2048"
            cert_name = SNI + ".crt"
            key_name = SNI + ".key"
            csr_name = SNI + ".csr"
            cert_dir_name = cert_name
            key_dir_name = key_name
            #root_cert = "certs/ca.pem"
            #root_key = "certs/ca.key"
            root_cert = "ca.cert"
            root_key = "ca.key"
            #keygen
            if not os.path.exists(key_dir_name):
                openssl_key = "openssl genrsa -out " + key_name + " 1024" #4096
                key_status = subprocess.check_call(openssl_key, shell = True)

            #WITHOUT AN IN COMMANDLINE INSTEAD IN .CONF FILE
            conf_name = SNI + ".conf"
            tmp_conf_name = "tmp_" + SNI + ".conf"
            #shutil.copy2("template.conf", tmp_conf_name)
            shutil.copy2("temp.conf", tmp_conf_name)


            #put CN in CN line
            repl_str = "CN                     = " + CN + "\n"
            def replace_line(file_name, line_num, text):
                lines = open(file_name, 'r').readlines()
                lines[line_num] = text
                out = open(file_name, 'w+')
                out.writelines(lines)
                #out.writelines("\n")
                out.close()
            replace_line(tmp_conf_name, 9, repl_str)


            #shutil.copy2("template.conf",conf_name)
            shutil.copy2(tmp_conf_name,conf_name)
            fp = open(conf_name,"a")
            tmp = []

            tmp = AN_tmp_list.split(',')
            for l in tmp:
                fp.write(l)
                fp.write('\n')
            fp.close()

            #WITH AN IN COMMANDLINE
            openssl_csr = "openssl req -new -key " + key_name + " -out " + csr_name + " -config " + conf_name
            csr_status = subprocess.check_call(openssl_csr, shell = True)

            #WITH AN IN COMMANDLINE
            #openssl_crt = "openssl x509 -req -days 365 -in certs/" + csr_name + " -CA ca.crt -CAkey ca.key -set_serial 0x12345 -out certs/" + cert_name


            openssl_crt = "openssl x509 -req -days 3546 -in " + csr_name + " -CA ca.crt -CAkey ca.key -set_serial 0x12345 -out " + cert_name + " -extensions v3_req -extfile " + conf_name #+ " *X509_EXTRA_ARGS"

            #openssl_crt = "openssl x509 req -in certs/" + csr_name + " -CA ca.crt -CAkey ca.key -CAcreateserial -out certs/" + cert_name + " -days 365"
            crt_status = subprocess.check_call(openssl_crt, shell = True)

            fake_context = ssl.create_default_context(purpose = ssl.Purpose.CLIENT_AUTH) #ssl.create_default_context() #ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            #fake_context.ssl.SSLContext(ssl.PROTOCOL_SSLv3)
            fake_context.load_cert_chain(certfile = cert_dir_name, keyfile = key_dir_name)
            #fake_context.verify_mode = ssl.CERT_OPTIONAL #ssl.CERT_OPTIONAL_NO_VERIFY#ssl.CERT_NONE
            request = None
            try:
                fake_proxy_socket = fake_context.wrap_socket(conn,server_side=True)#, do_handshake_on_connect=True , certfile = cert_dir_name, keyfile = key_dir_name)#, do_handshake_on_connect=True)#, server_hostname = client_IP)#, certfile = "ca.crt", keyfile = "ca.key")#, keyfile=p1, certfile=fake_cert, do_handshake_on_connect=True)
                #fake_proxy_socket.ssl_verify_cert_chain()
                #fake_proxy_socket.do_handshake()
                #fake_proxy_socket.settimeout(self.timeout)
                request = fake_proxy_socket.recv(MAXBUF)
                try:
                    #print 'decoded: {}'.format(request)
                    pass
                except Exception as e:
                    print e
                    print request
            #try:

            except ssl.SSLError, err:
                if err.args[1].find("sslv3 alert") == -1:
                    raise
            real_proxy_socket.send(request)
            reply = ''

            while True:

                reply = real_proxy_socket.recv(MAXBUF)
                if len(reply) > 0:
                    fake_proxy_socket.send(reply)
                else:
                    break
            '''
            reply = real_proxy_socket.recv(MAXBUF)
            print "REPLY"
            print reply
            fake_proxy_socket.sendall(reply)
            #print "HELLO\n"
            '''
            #fake_cert = fake_proxy_socket.getpeercert()
            #print "FAKE _CERT: "
            #print fake_cert
            #print "HELLO"
            #ssl_req_data = conn.recv(MAXBUF)
            #print "DATA:"
            #print ssl_req_data
            real_proxy_socket.close()
            fake_proxy_socket.close()
            proxy_socket.close()
            conn.close()

	#PROCESS HTTP REQUEST
        else:
            print "Connect to HTTP:", hostname, port
	    #IP USED FOR WIRESHARK PURPOSES
            #IP = socket.gethostbyname(hostname)
            #print "IP :" + IP
            try:
                proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                proxy_socket.connect((unicode(hostname), port))
                #proxy_socket.connect((hostname, port))
                proxy_socket.send(data)
                #SEND HTTP REQUEST FROM MY PROXY TO SERVER AND RECEIVE REPLY
                #reply = ""
                while True:
                    if self.timeout is not -1:
                        try:
			    conn.settimeout(self.timeout)
		    	    data = conn.recv(MAXBUF)
		    	    conn.settimeout(None)
	    		except socket.timeout as to:
			    print "WARNING: socket.timeout : timed out"
			    raise to
                    else:
                        reply = proxy_socket.recv(MAXBUF)
                    if log:
                        #self.wr_lock.release()
                        flag = False
                        self.end_wr_append_log(client_IP, hostname, reply, flag)
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
                self.sem_lock.release()
                sys.exit(1)
        #UNCOMMENT FOR NO DEFAULT THREADPOOL
        #if self.numworker is not 10:
        self.sem_lock.release()

#MAIN
if __name__ == '__main__':
    numworker = 10
    timeout = -1
    parseargs = argparse.ArgumentParser()

    parseargs.add_argument('-v', '--version', version=0.1, action='version', help='Prints the name of the application, the version number (in this case the version has to be 0.1), the author and exists, returning 0.')
    parseargs.add_argument('-p', '--port', type=int, required=True, help='Required port your server will be listening on. If the port you try to listen is already occupied, just try another.')
    parseargs.add_argument('-n', '--numworker', type=int, default=10, help='This parameter specifies the number of workers in the thread pool used for handling concurrent HTTP requests. (default: 10).')
    parseargs.add_argument('-t', '--timeout', type=int, default=-1, help='Time to wait before giving ip waiting for response form server. Default is one.')
    parseargs.add_argument('-l', '--log', type=str, help='Logs all the HTTP requests and their corresponding responses under the directory specified by log.')
    args = parseargs.parse_args()

    if args.log:
        log = True
        log_dir_cmd = "mkdir " + args.log
        os.system(log_dir_cmd)
    if args.port < 1 or args.port > 65535:
        print "ERROR: Put a port number between 1 and 65535\n"
        sys.exit(0)
    if args.numworker < 1 or args.numworker > 255:
        print "ERROR: Put a number for the workers between 1 and 255\n"
        sys.exit(0)

    proxy = ProxyRequestHandler(args.port, args.log, args.numworker, args.timeout)
    proxy.run()
