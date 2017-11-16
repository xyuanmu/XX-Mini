import ConfigParser
import os
import re
import sys
import socket

from xlog import getLogger
xlog = getLogger("gae_proxy")

from OpenSSL import version as openssl_version

__mini_version__ = '1.3.3'
file_path = os.path.dirname(os.path.abspath(__file__))
current_path = os.path.abspath(os.path.join(file_path, os.pardir))


class Config(object):

    def load(self):
        """load config from proxy.ini"""
        ConfigParser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')
        self.CONFIG = ConfigParser.ConfigParser()
        self.CONFIG_FILENAME = os.path.abspath( os.path.join(current_path, 'proxy.ini'))
        self.CONFIG.read(self.CONFIG_FILENAME)

        self.DATA_PATH = os.path.abspath( os.path.join(current_path, 'data'))
        if not os.path.isdir(self.DATA_PATH):
            self.DATA_PATH = current_path

        # load ../data/manual.ini, set by user
        self.MANUAL_LOADED = False
        self.CONFIG_MANUAL_FILENAME = os.path.abspath( os.path.join(self.DATA_PATH, 'manual.ini'))
        if os.path.isfile(self.CONFIG_MANUAL_FILENAME):
            try:
                self.CONFIG.read(self.CONFIG_MANUAL_FILENAME)
                self.MANUAL_LOADED = 'manual.ini'
            except Exception as e:
                xlog.exception("data/manual.ini load error:%s", e)

        self.LISTEN_IP = self.CONFIG.get('listen', 'ip')
        self.LISTEN_PORT = self.CONFIG.getint('listen', 'port')
        self.LISTEN_USERNAME = self.CONFIG.get('listen', 'username') if self.CONFIG.has_option('listen', 'username') else ''
        self.LISTEN_PASSWORD = self.CONFIG.get('listen', 'password') if self.CONFIG.has_option('listen', 'password') else ''
        self.LISTEN_VISIBLE = self.CONFIG.getint('listen', 'visible')
        self.LISTEN_DEBUGINFO = self.CONFIG.getint('listen', 'debuginfo')

        self.PUBLIC_APPIDS = [x.strip() for x in self.CONFIG.get('gae', 'public_appid').split("|")]
        self.GAE_APPIDS = [x.strip() for x in self.CONFIG.get('gae', 'appid').split("|")] if self.CONFIG.get('gae', 'appid') else []
        self.GAE_PASSWORD = self.CONFIG.get('gae', 'password').strip()
        self.GAE_VALIDATE = self.CONFIG.getint('gae', 'validate')

        fwd_endswith = []
        fwd_hosts = []
        direct_endswith = []
        direct_hosts = []
        gae_endswith = []
        gae_hosts = []
        for k, v in self.CONFIG.items('hosts'):
            if v == "fwd":
                if k.startswith('.'):
                    fwd_endswith.append(k)
                else:
                    fwd_hosts.append(k)
            elif v == "direct":
                if k.startswith('.'):
                    direct_endswith.append(k)
                else:
                    direct_hosts.append(k)
            elif v == "gae":
                if k.startswith('.'):
                    gae_endswith.append(k)
                else:
                    gae_hosts.append(k)
        self.HOSTS_FWD_ENDSWITH = tuple(fwd_endswith)
        self.HOSTS_FWD = tuple(fwd_hosts)
        self.HOSTS_GAE_ENDSWITH = tuple(gae_endswith)
        self.HOSTS_GAE = tuple(gae_hosts)
        self.HOSTS_DIRECT_ENDSWITH = tuple(direct_endswith)
        self.HOSTS_DIRECT = tuple(direct_hosts)

        self.AUTORANGE_THREADS = self.CONFIG.getint('autorange', 'threads')
        self.AUTORANGE_MAXSIZE = self.CONFIG.getint('autorange', 'maxsize')

        self.PAC_ENABLE = self.CONFIG.getint('pac', 'enable')
        self.PAC_IP = self.CONFIG.get('pac', 'ip')
        self.PAC_PORT = self.CONFIG.getint('pac', 'port')
        self.PAC_FILE = self.CONFIG.get('pac', 'file').lstrip('/')
        self.PAC_GFWLIST = self.CONFIG.get('pac', 'gfwlist')
        self.PAC_ADMODE = self.CONFIG.getint('pac', 'admode')
        self.PAC_ADBLOCK = self.CONFIG.get('pac', 'adblock') if self.PAC_ADMODE else 0
        self.PAC_EXPIRED = self.CONFIG.getint('pac', 'expired')

        self.PROXY_ENABLE = self.CONFIG.getint('proxy', 'enable')
        self.PROXY_TYPE = self.CONFIG.get('proxy', 'type')
        self.PROXY_HOST = self.CONFIG.get('proxy', 'host')
        self.PROXY_PORT = self.CONFIG.get('proxy', 'port')
        if self.PROXY_PORT == "":
            self.PROXY_PORT = 80
        else:
            self.PROXY_PORT = int(self.PROXY_PORT)
        self.PROXY_USER = self.CONFIG.get('proxy', 'user')
        self.PROXY_PASSWD = self.CONFIG.get('proxy', 'passwd')

        self.USE_IPV6 = self.CONFIG.getint('google_ip', 'use_ipv6')
        self.max_links_per_ip = self.CONFIG.getint('google_ip', 'max_links_per_ip')

        self.https_max_connect_thread = config.CONFIG.getint("connect_manager", "https_max_connect_thread")
        self.connect_interval = config.CONFIG.getint("connect_manager", "connect_interval")

        self.version = __mini_version__
        self.log_file = config.CONFIG.getint("system", "log_file")
        self.log_scan = config.CONFIG.getint("system", "log_scan") if config.CONFIG.has_option("system", "log_scan") else False

        # change to True when finished import CA cert to browser
        self.cert_import_ready = False


    @staticmethod
    def get_listen_ip():
        listen_ip = '127.0.0.1'
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(('8.8.8.8', 53))
            listen_ip = sock.getsockname()[0]
        except StandardError:
            pass
        finally:
            if sock:
                sock.close()
        return listen_ip


    def summary(self):
        pac_ip = self.get_listen_ip() if self.PAC_IP != '127.0.0.1' else self.PAC_IP
        info  = '-'*80
        info += '\nXX-Mini Version     : %s (python/%s pyopenssl/%s)\n' % (self.version, sys.version.split()[0], openssl_version.__version__)
        info += 'Listen Address      : %s:%d\n' % (self.LISTEN_IP if self.LISTEN_IP == '127.0.0.1' else self.get_listen_ip(), self.LISTEN_PORT)
        info += 'Setting File        : %sproxy.ini\n' % (self.MANUAL_LOADED + '/' if self.MANUAL_LOADED else '')
        info += '%s Proxy %s : %s:%s\n' % (self.PROXY_TYPE, ' '*(12-len(self.PROXY_TYPE)), self.PROXY_HOST, self.PROXY_PORT) if self.PROXY_ENABLE else ''
        info += 'GAE APPID           : %s\n' % ('Proud to Use My APPID' if self.GAE_APPIDS else 'Using Public APPID')
        info += 'Pac Server          : http://%s:%d/%s\n' % (pac_ip, self.PAC_PORT, self.PAC_FILE) if self.PAC_ENABLE else ''
        info += 'CA File             : http://%s:%d/%s\n' % (pac_ip, self.PAC_PORT, 'CA.crt') if self.PAC_ENABLE else ''
        info += 'Pac File            : file://%s\n' % os.path.abspath(os.path.join(self.DATA_PATH , self.PAC_FILE)) if self.PAC_ENABLE else ''
        info += '-'*80
        return info


config = Config()
config.load()
