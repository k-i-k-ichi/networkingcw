#!/usr/bin/python

from copy import copy
from optparse import OptionParser, OptionValueError
import pprint
from random import seed, randint
import struct
from socket import *
from sys import exit, maxint as MAXINT
from time import time, sleep

from gz01.collections_backport import OrderedDict
from gz01.dnslib.RR import *
from gz01.dnslib.Header import Header
from gz01.dnslib.QE import QE
from gz01.inetlib.types import *
from gz01.util import *

# timeout in seconds to wait for reply
TIMEOUT = 5

# domain name and internet address of a root name server
ROOTNS_DN = "f.root-servers.net."   
ROOTNS_IN_ADDR = "192.5.5.241"

class ACacheEntry:
  ALPHA = 0.8

  def __init__(self, dict, srtt = None):
    self._srtt = srtt
    self._dict = dict

  def __repr__(self):
    return "<ACE %s, srtt=%s>" % \
      (self._dict, ("*" if self._srtt is None else self._srtt),)

  def update_rtt(self, rtt):
    old_srtt = self._srtt
    self._srtt = rtt if self._srtt is None else \
      (rtt*(1.0 - self.ALPHA) + self._srtt*self.ALPHA)
    logger.debug("update_rtt: rtt %f updates srtt %s --> %s" % \
       (rtt, ("*" if old_srtt is None else old_srtt), self._srtt,))

class CacheEntry:
  def __init__(self, expiration = MAXINT, authoritative = False):
    self._expiration = expiration
    self._authoritative = authoritative

  def __repr__(self):
    now = int(time())
    return "<CE exp=%ds auth=%s>" % \
           (self._expiration - now, self._authoritative,)

class CnameCacheEntry:
  def __init__(self, cname, expiration = MAXINT, authoritative = False):
    self._cname = cname
    self._expiration = expiration
    self._authoritative = authoritative

  def __repr__(self):
    now = int(time())
    return "<CCE cname=%s exp=%ds auth=%s>" % \
           (self._cname, self._expiration - now, self._authoritative,)




# >>> entry point of ncsdns.py <<<

# Seed random number generator with current time of day:
now = int(time())
seed(now)

# Initialize the pretty printer:
pp = pprint.PrettyPrinter(indent=3)

# Initialize the name server cache data structure; 
# [domain name --> [nsdn --> CacheEntry]]:
nscache = dict([(DomainName("."), 
            OrderedDict([(DomainName(ROOTNS_DN), 
                   CacheEntry(expiration=MAXINT, authoritative=True))]))])

# Initialize the address cache data structure;
# [domain name --> [in_addr --> CacheEntry]]:
acache = dict([(DomainName(ROOTNS_DN),
           ACacheEntry(dict([(InetAddr(ROOTNS_IN_ADDR),
                       CacheEntry(expiration=MAXINT,
                       authoritative=True))])))]) 

# Initialize the cname cache data structure;
# [domain name --> CnameCacheEntry]
cnamecache = dict([])

# Parse the command line and assign us an ephemeral port to listen on:
def check_port(option, opt_str, value, parser):
  if value < 32768 or value > 61000:
    raise OptionValueError("need 32768 <= port <= 61000")
  parser.values.port = value

parser = OptionParser()
parser.add_option("-p", "--port", dest="port", type="int", action="callback",
                  callback=check_port, metavar="PORTNO", default=0,
                  help="UDP port to listen on (default: use an unused ephemeral port)")
(options, args) = parser.parse_args()

# Create a server socket to accept incoming connections from DNS
# client resolvers (stub resolvers):
ss = socket(AF_INET, SOCK_DGRAM)
ss.bind(("127.0.0.1", options.port))
serveripaddr, serverport = ss.getsockname()

# NOTE: In order to pass the test suite, the following must be the
# first line that your dns server prints and flushes within one
# second, to sys.stdout:
print "%s: listening on port %d" % (sys.argv[0], serverport)
sys.stdout.flush()

# Create a client socket on which to send requests to other DNS
# servers:
setdefaulttimeout(TIMEOUT)
cs = socket(AF_INET, SOCK_DGRAM)
 
# Lookup address in nscache
def nscache_lookup(string, cache):
  print "125"
  result_dict_obj = cache.get(string)

  print "127"
  
  while result_dict_obj == None:
    index = 0
    print string[index:]
    index = string.find('.', delimiter_index) + 1 
    if index >= len(string):
      index = len(string) - 1
    result_dict_obj = cache.get(string[index:])
  return result_dict_obj
   
   
   
    
# This is a simple, single-threaded server that takes successive
# connections with each iteration of the following loop:
while 1:
  (data, address,) = ss.recvfrom(512) # DNS limits UDP msgs to 512 bytes
  if not data:
    log.error("client provided no data")
    continue

  header = Header.fromData(data)
  question = QE.fromData(data, len(header))

  cs.sendto(data, (ROOTNS_DN, 53))
  (reply, _,) = cs.recvfrom(512)
  reply_header = Header.fromData(data)

  # create query stack
  query_stack = [] 
  current_query_name = str(question._dn)
  print "153"

  # lookup_cache for the longest dns that match the query name:
  ns_list = nscache_lookup(current_query_name, nscache) 
  print "lookup not fail"

  # add the first query into stack
  for dn_object in reverse(ns_list.items()):
    query_stack.append((str(question._dn), str(dn_object)))

  current_query_name = query_stack.pop()[1]

  print current_query_name
  last_matching_length = 0 
  # while 1: 
    # Add reply authoritive section to dn cache
    # Add reply glue entry to address cache
    # Search in cache for the longest machting of domain name - dns name
      # matching_length = substringlength(current_query_name, cache_match)
    # Search in addr cache for address of that domainname
    # if dnserver not found in address cache
      # add current_query_name to cache
      # current_query_name = dnserver name
      # continue
    # if reply header answer count != 0 and stack.size() != 0 
      # current_query_name = stack.pop()
      # continue
    # else if reply header answer count != 0 and stack.size() == 0
      # break
    # else if (if we are not making progress)
      # break  

    
        
  
  logger.log(DEBUG2, "our reply in full:") 
  logger.log(DEBUG2, hexdump(reply))

  ss.sendto(reply, address)
