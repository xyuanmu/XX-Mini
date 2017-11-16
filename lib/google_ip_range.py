import random
import time
import os
import sys
import struct
import threading
import ip_utils
from config import config

random.seed(time.time()* 1000000)

from xlog import getLogger
xlog = getLogger("gae_proxy")

file_path = os.path.dirname(os.path.abspath(__file__))
current_path = os.path.abspath(os.path.join(file_path, os.pardir))


class IpPool(object):
    def __init__(self):
        self.txt_ip_fn = os.path.join(current_path, "ip_checked.txt")
        self.bin_ip_fn = os.path.join(config.DATA_PATH, "ip_checked.bin")
        self.bin_fd = None
        threading.Thread(target=self.init).start()

    def init(self):
        if not self.check_bin():
            self.generate_bin()
        self.bin_fd = open(self.bin_ip_fn, "rb")
        self.bin_size = os.path.getsize(self.bin_ip_fn)

    def check_bin(self):
        if not os.path.isfile(self.bin_ip_fn):
            return False

        if os.path.getmtime(self.bin_ip_fn) < os.path.getmtime(self.txt_ip_fn):
            return False

        return True

    def generate_bin(self):
        xlog.info("generating binary ip pool file.")
        rfd = open(self.txt_ip_fn, "rt")
        wfd = open(self.bin_ip_fn, "wb")
        num = 0
        for line in rfd.readlines():
            ip = line
            try:
                ip_num = ip_utils.ip_string_to_num(ip)
            except Exception as e:
                xlog.warn("ip %s not valid in %s", ip, self.txt_ip_fn)
                continue
            ip_bin = struct.pack("<I", ip_num)
            wfd.write(ip_bin)
            num += 1

        rfd.close()
        wfd.close()
        xlog.info("finished generate binary ip pool file, num:%d", num)

    def random_get_ip(self):
        while self.bin_fd is None:
            time.sleep(1)
        for _ in range(5):
            position = random.randint(0, self.bin_size/4) * 4
            self.bin_fd.seek(position)
            ip_bin = self.bin_fd.read(4)
            if ip_bin is None:
                xlog.warn("ip_pool.random_get_ip position:%d get None", position)
            elif len(ip_bin) != 4:
                xlog.warn("ip_pool.random_get_ip position:%d len:%d", position, len(ip_bin))
            else:
                ip_num = struct.unpack("<I", ip_bin)[0]
                ip = ip_utils.ip_num_to_string(ip_num)
                return ip
        time.sleep(3)
        raise Exception("get ip fail.")


class IpRange(object):
    def __init__(self):
        if config.USE_IPV6:
            self.default_range_file = os.path.join(current_path, "ip_range_ipv6.txt")
            self.user_range_file = os.path.join(config.DATA_PATH, "ip_range_ipv6.txt")
        else:
            self.default_range_file = os.path.join(current_path, "ip_range.txt")
            self.user_range_file = os.path.join(config.DATA_PATH, "ip_range.txt")

        ip_source = config.CONFIG.get("google_ip", "ip_source")
        if ip_source == "ip_pool" and not config.USE_IPV6:
            self.ip_pool = IpPool()
            self.get_ip = self.ip_pool.random_get_ip
            xlog.info("Use google ip pool.")
        else:
            self.load_ip_range()

    def load_range_content(self, default=False):
        if not default and os.path.isfile(self.user_range_file):
            self.range_file = self.user_range_file
        else:
            self.range_file = self.default_range_file

        xlog.info("load ip range file:%s", self.range_file)
        fd = open(self.range_file, "r")
        if not fd:
            xlog.error("load ip range %s fail", self.range_file)
            return

        content = fd.read()
        fd.close()
        return content

    def load_ip_range(self):
        self.ip_range_map = {}
        self.ip_range_list = []
        self.candidate_amount_ip = 0

        lines = []
        content = self.load_range_content()
        raw_lines = content.splitlines()
        for ip_line in raw_lines:
            ip_line = ip_line.replace(' ', '')
            if len(ip_line) == 0 or ip_line[0] == '#':
                continue
            ips = ip_line.split("|")
            for ip in ips:
                if len(ip) == 0:
                    continue
                lines.append(ip)

        if config.USE_IPV6:
            self.ipv6_list = lines
            return

        for line in lines:
            if len(line) == 0 or line[0] == '#':
                continue

            try:
                begin, end = ip_utils.split_ip(line)
                nbegin = ip_utils.ip_string_to_num(begin)
                nend = ip_utils.ip_string_to_num(end)
                if not nbegin or not nend or nend < nbegin:
                    xlog.warn("load ip range:%s fail", line)
                    continue
            except Exception as e:
                xlog.exception("load ip range:%s fail:%r", line, e)
                continue

            self.ip_range_map[self.candidate_amount_ip] = [nbegin, nend]
            self.ip_range_list.append( [nbegin, nend] )
            num = nend - nbegin
            self.candidate_amount_ip += num

    def get_ip(self):
        if config.USE_IPV6:
            return random.choice(self.ipv6_list)
        else:
            while True:
                index = random.randint(0, len(self.ip_range_list) - 1)
                ip_range = self.ip_range_list[index]
                #xlog.debug("random.randint %d - %d", ip_range[0], ip_range[1])
                if ip_range[1] == ip_range[0]:
                    return ip_utils.ip_num_to_string(ip_range[1])

                try:
                    id_2 = random.randint(0, ip_range[1] - ip_range[0])
                except Exception as e:
                    xlog.exception("random.randint:%r %d - %d, %d", e, ip_range[0], ip_range[1], ip_range[1] - ip_range[0])
                    return

                ip = ip_range[0] + id_2
                add_last_byte = ip % 256
                if add_last_byte == 0 or add_last_byte == 255:
                    continue

                return ip_utils.ip_num_to_string(ip)

ip_range = IpRange()