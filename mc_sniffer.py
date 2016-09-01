# -*- coding: utf-8 -*-
#! /usr/bin/env python2.7

import sys
import os
import pcap
import string
import time
import socket
import struct
import threading
import re
import subprocess
import MySQLdb
import MySQLdb.constants
import MySQLdb.converters
import MySQLdb.cursors
import logging
from logging import handlers
from multiprocessing import Process
from multiprocessing import Pipe
from multiprocessing import Queue
from multiprocessing import Value
import signal

# alias
logger = None

def log_init():

    log_level = logging.DEBUG
    log_filename = "/tmp/sinffer_mc.log"
    logger = logging.getLogger("main")
    logger.setLevel(log_level)
    handler = handlers.RotatingFileHandler(log_filename, maxBytes=20000000, backupCount=0)
    formatter = logging.Formatter("%(asctime)s - [%(levelname)s] - [%(filename)s: %(lineno)d] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger

class Parser(Process):
    '''
    '''
    def __init__(self, queue, pipe, ip, state, port=11211):

        Process.__init__(self)
        self.queue = queue
        self.key_map = {}
        self.port = port
        self.ip = ip
        self.pipe = pipe
        self.state = state
        self.rets = []
        self.pces = []

    def get_init(self):
        '''
            desc: init value of every mc key
            param: none
            return: dict of init data
        '''
        return {"get":0, "set":0, "delete":0, "incr":0, "decr":0, "objsize":0, "bytes":0}

    def getres(self):
        '''
            desc: regrex of every command pattern of mc
            param: none
            return: dict
        '''
        return {"delete": re.compile("delete (\S+)"),"gets": re.compile("gets (\S+)"),
                "get": re.compile("get (\S+)"),"incr": re.compile("incr (\S+) (\S+)"),"decr": re.compile("decr (\S+) (\S+)"),
                "set": re.compile("set (\S+) (\S+) (\S+) (\S+)"),
                'VALUE': re.compile("VALUE (\S+) (\S+) (\S+)")}

    def decode_ip_packet(self, pkt):
        '''
            desc: it is used only in text protocol
            param: mac packet
            return: (re_groups[0], key, re_groups)
        '''
        d = {}
        d['header_len'] = ord(pkt[14:15]) & 0x0f
        if d['header_len'] > 5:
            d['options'] = pkt[34:4*(d['header_len']-5)]
        else:
            d['options']=None
        # mac_header + ip_header
        rawdata = pkt[14+4*d['header_len']:]
        for k, v in self.getres().items():
            re_result = v.search(rawdata)
            if re_result:
                re_groups = re_result.groups()
                return re_groups[0], k, re_groups

        return None, None, None

    def calc(self, pkt, key, k, re_groups):
        '''
            desc: collect and gather keys and commands we need
            param: mac packet, key, command, re_groups
            return: none
        '''
        objsize = 0
        if k == 'set':
            self.key_map[key]["set"] += 1
            objsize = int(re_groups[3])
        if k == 'VALUE':
            objsize = int(re_groups[2])
        else:
            pass
        if k == "get" or k == "gets":
            self.key_map[key]["get"] += 1
        elif k == "incr":
            self.key_map[key]["incr"] += 1
        elif k == "decr":
            self.key_map[key]["decr"] += 1
        elif k == "delete":
            self.key_map[key]["delete"] += 1
        else:
            pass
        self.key_map[key]["objsize"] = objsize
        if objsize > 1460:
            total_bytes = (objsize / 1460)*1518 + objsize % 1460 + 40 + 18
            self.key_map[key]["bytes"] += total_bytes
        else:
            try:
                # 14 bytes mac header and 4 bytes mac tailer
                common_bytes = socket.ntohs(struct.unpack('H',pkt[16:18])[0]) + 18
                self.key_map[key]["bytes"] += common_bytes
            except:
                logger.debug("parse packet bytes exception, check 'socket.ntohs(...)'.")


    def filter(self, dt):
        '''
            desc: filter out non-sense records
            param: self.key_map
            return: none
        '''
        keys = dt.keys()
        for mc_key in keys:
            if dt[mc_key]["get"] == 0 and dt[mc_key]["set"] == 0 and dt[mc_key]["delete"] == 0 and dt[mc_key]["incr"] == 0 and dt[mc_key]["decr"] == 0:
                del dt[mc_key]

    def sorting(self, que, column):
        '''
            desc: get the most 200 calls of each command of each key
        '''
        its = self.key_map.items()
        col_list = sorted(its, key=lambda x: x[1][column], reverse=True)
        if col_list > 200:
            col_list = col_list[:200]

        que.put(dict(col_list).keys())

    def print_results(self):
        '''
        '''
        self.filter(self.key_map)
        for col in ["get", "set", "delete", "incr", "decr", "bytes", "objsize"]:
            que = Queue(1)
            self.rets.append(que)
            p = Process(target=self.sorting, args=(que,col))
            self.pces.append(p)
        for pc in self.pces:
            pc.start()
        for pc in self.pces:
            pc.join()
        key_set = set()
        for q in self.rets:
            key_set.update(q.get())
        param = []
        for key in key_set:
            param.append([self.port, self.ip, key, self.key_map[key]["get"], self.key_map[key]["set"],self.key_map[key]["delete"], self.key_map[key]["incr"], self.key_map[key]["decr"], self.key_map[key]["objsize"], self.key_map[key]["bytes"]])

        # write to db
        sql = '''insert into ...'''
        conn_3304_write.executemany(sql, param)
        conn_3304_write.commit()
        logger.info("{0}_{1} records done commit.".format(self.port, self.ip))

    def run(self):

        self.pipe.recv()
        logger.info("start parsing packets from queue...")
        while 1:
            try:
                pkt = self.queue.get(block=True, timeout=2)
            except:
                break
            if not pkt:
                logger.debug("encountered a None pkt ... stop parsering !")
                break
            if pkt[12:14] == '\x08\x00':
                key, operation, re_groups = self.decode_ip_packet(pkt)
                if key:
                    if key not in self.key_map:
                        self.key_map[key] = self.get_init()
                    self.calc(pkt, key, operation, re_groups)

        logger.info("stop parsing packets.")
        logger.info("sorting results, uniting keys and storing to MySQL.")
        self.print_results()

class Capture(Process):
    '''
    '''
    def __init__(self, state=None, queue=None, pipe=None, dev="lo", port=11211):

        Process.__init__(self)
        self.pack_recv = -1
        self.pack_drop = -1
        self.pktlen = 0
        self.timestamp = -1
        self.lost_pkt = 0
        self.dev = dev
        self.port = port
        self.pipe = pipe
        self.queue = queue
        self.state = state
        self.check()
        self.prepare()
        self.init_signal()

    def init_signal(self):

        def handler(a,b):
            self.state.value = 0

        signal.signal(signal.SIGALRM, handler)

    def check(self):
        if not self.state or not self.pipe or not self.queue:
            logger.info("argument error of Capture class.")
            sys.exit(1)

    def prepare(self):
        '''
        '''
        self.p = pcap.pcapObject()
        self.p.open_live(self.dev, 1500, 0, 100)
        self.p.setfilter("port %d" % self.port, 0, 0)

    def run(self):

        self.pipe.send("1")
        logger.info("start capturing port {0}...".format(self.port))
        def sendto(pktlen, data, timestamp):
            if not data:
                return
            self.pktlen = pktlen
            self.timestamp = timestamp
            try:
                self.queue.put(data, block=False)
            except:
                self.lost_pkt += 1
            return

        signal.alarm(1)
        try:
            while self.state.value:
                self.p.loop(1, sendto)
        except:
            logger.debug("%s" % sys.exc_type)
            logger.debug("shutting down")
        stat = self.p.stats()
        self.pack_recv = stat[0]
        self.pack_drop = stat[1]
        # 参考 http://bryceboe.com/2011/01/28/the-python-multiprocessing-queue-and-large-objects/#ref1
        # close 以后会把 buffer 中的数据 flush 到 pipe 中，看下这个能不能解决问题
        self.queue.close()
        self.queue.cancel_join_thread()
        logger.info("{0}'s capture process canceled join thread of queue.".format(self.port))
        signal.alarm(0)
        logger.info("{0} pack_recv: {1}".format(self.port, self.pack_recv))
        logger.info("{0} pack_drop: {1}".format(self.port, self.pack_drop))
        logger.info("{0} pack_lost: {1}".format(self.port, self.lost_pkt))

def usage():

    print "usage        "
    print
    print "{0} iface ip port".format(sys.argv[0])
    print 'Example: {0} eth0 10.55.23.25 11211'.format(sys.argv[0])

    sys.exit(1)

def daemonize():

    """Performs the necessary dance to become a background daemon."""

    if os.fork():
        os._exit(0)
    os.chdir("/")
    os.umask(022)
    os.setsid()
    os.umask(0)
    if os.fork():
        os._exit(0)
    stdin = open(os.devnull)
    stdout = open(os.devnull, 'w')
    os.dup2(stdin.fileno(), 0)
    os.dup2(stdout.fileno(), 1)
    os.dup2(stdout.fileno(), 2)
    stdin.close()
    stdout.close()
    for fd in xrange(3, 1024):
        try:
            os.close(fd)
        except OSError:  # This FD wasn't opened...
            pass         # ... ignore the exception.

if __name__=='__main__':

    if len(sys.argv) != 4:
        usage()

    iface = sys.argv[1]
    ip = sys.argv[2]
    port = sys.argv[3]

    daemonize()
    logger = log_init()

    pipe = Pipe()
    queue = Queue(8000)
    value = Value('i', 1)
    cp = Capture(pipe=pipe[1], queue=queue, state=value, dev=iface, port=port)
    psr = Parser(pipe=pipe[0], queue=queue, state=value, port=port, ip=ip)
    psr.start()
    cp.start()
    cp.join()
    psr.join()
    logger.debug("handle port{0}: {1} done.".format(count, port))
