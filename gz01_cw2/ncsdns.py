#!/usr/bin/python

from copy import copy, deepcopy
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
 
# Lookup method for longest match in nscache, return OrderedDict() 
def nscache_lookup(string, cache):
  result_dict_obj = cache.get(string)
  iterate = 1
  index = 0
  while result_dict_obj == None:
    index = string.find(".", index) + 1 
    if index >= len(string):
      index = len(string) - 1
    tempobj = DomainName(string[index:])
    result_dict_obj = cache.get(tempobj)
  return result_dict_obj # Type OrderedDict 
   
# Lookup method for ns address in acache, return object 
def acache_lookup(string, cache):
  result_obj = acache.get(DomainName(string))
  return result_obj # Type AcacheEntry

# This is a simple, single-threaded server that takes successive
# connections with each iteration of the following loop:
  
while 1:
  (data, address,) = ss.recvfrom(512) # DNS limits UDP msgs to 512 bytes
  if not data:
    log.error("client provided no data")
    continue
  # create query stack
  query_stack = [] 


  header = Header.fromData(data)
  question = QE.fromData(data, len(header))
  ## Check acache 
  if acache_lookup(question._dn, acache) != None:
    result_from_cache = acache_lookup(question._dn, acache)
    reply_header = Header(header._id, header._opcode, header_rcode, header._qdcount,
                           1, 0, 0, True, False, header._tc, header._rd, header._ra)
    reply_QE = deepcopy(header) 
    reply_RR = RR_A(question._dn, result_from_cache._dict.items()[0][1]._expiration, 
                                            toNetwork(result_from_cache._dict.items()[0][0]))
    reply_packet = reply_header.pack() + reply_QE.pack() + reply_RR.pack()
    ss.sendto(reply, address)
    continue
  cs.sendto(data, (ROOTNS_DN, 53))
  
  # lookup_cache for the longest dns that match the query name:
  dn_dict = nscache_lookup(str(question._dn), nscache) 
  
  # compose new question query for each 
  for item in dn_dict:
    query_packet = deepcopy(data) 
    # add all the  query into stack
    query_stack.append((query_packet, str(item[0]))
  
  # recursive query part
  while 1: 
    (cur_query_packet, cur_query_addr,) = query_stack.pop()

    # search through acache for query address  
    search_result_obj = acache_lookup(cur_query_addr, acache)    
    
    # Failed search 
    if search_result_obj == None:
      # return current_query_name to cache
      query_stack.append((cur_query_packet, cur_query_addr))
      # contruct a new query object for this NS that we dont have addr for
      new_header = deep_copy(header)
      new_qe = QE(1, DomainName(str(curr_query_addr)))
      next_query_packet = new_header.pack() + new_qe.pack()

      # add a new query for the dns address to query_stack
      # search this NS IP back from the top
      query_stack.append(next_query_packet, ROOTNS_DN) 
      continue

    cur_query_dns_address = str(search_result_obj._dict.items()[0][0])
    ### I wish you could see 
    ### My misery mind
    ### Trying to get this variable assigned 
    ### They should apologize
    ### Whoever designed this API

    # send query and receive query
    cs.sendto(cur_query_packet, (str(cur_query_dns_address), 53))
    (response, xyz,) = cs.recvfrom(512)
    
    # parse query
    response_header = Header.fromData(response)
    response_QE = QE.fromData(response, len(response_header))
    (response_rr, response_rr_len,) = RR.fromData(response, len(response_header) + len(response_QE))
 
 
    # If contains Answer section
    if reponse_header._ancount > 0:
       
      rr_ar_temp = response_rr
      rr_ar_temp_len = response_rr_len

      # If of type A 
      if rr_ar_temp._type == 1:
        # add to cache
        if acache.get(rr_ar_temp._dn) != None:
          acache.get(rr_ar_temp._dn).update_rtt(rr_ar_temp._ttl)  
        else:
          acache[rr_ar_temp._dn] = ACacheEntry(dict([InetAddr(inet_ntoa(rr_ar_temp._inaddr)),
                                      CacheEntry(expiration=rr_ar_temp._ttl,
                                                        authoritative=True))])
        # if answer is what we are looking for
        if rr_ns_temp._dn == question._dn:
          break:
        else:
          # clear all stack up until the point of a different query
          while len(query_size) && ( query_stack[len(query_stack)-1:] == cur_query_packet ):
            query_stack.pop() 
          continue
      # else if Cname
      else if rr_ar_temp._type == 5:
        break

    # If the only authoritive record is SOA 
    # Terminate and construct a return message
    if reponse_header._nscount == 1:
      (rr_ns_temp, rr_ns_temp_len,) = RR.fromData(response, len(response_header) + len(response_QE)) 
      if rr_ns_temp._type == 6:
       break 

    # If contains Authoritive NS section
    if response_header._nscount > 0:
      rr_ns_offset = len(response_header) + len(response_QE) 
      for i in range(0, response_header._nscount):
        (rr_ns_temp, rr_ns_temp_len,) = RR.fromData(response, rr_ns_offset)
        
        # For every Name server Entries
        if rr_ns_temp._type == 2:
          # add to cache
            # If domainname already in cache update
            if nscache.get(rr_ns_temp._dn) != None:
              # update domainname dict value 
              nscache.get(rr_ns_temp._dn)[DomainName(str(rr_ns_temp._nsdn))] = CacheEntry(expiration=MAXINT,
                                                                              authoritative=True)
            else:
              # update nscache dict value
              nscache[rr_ns_temp._dn] = OrderedDict([(DomainName(str(rr_ns_temp._nsdn)), 
                                 CacheEntry(expiration=MAXINT, authoritative=True))]))]) 
          # construct new query packet 
          temp_query_packet = deepcopy(cur_query_packet)
          # Add to stack
          query_stack.append((temp_query_packet, str(rr_ns_temp._nsdn)))
        rr_ns_offset += rr_ns_temp_len

    # If contains additional record
    if response_header._arcount > 0
      rr_ar_offset = rr_ns_offset
      for i in range(0, response_header._arcount):
        (rr_ar_temp, rr_ar_temp_len,) = RR.fromData(response, rr_ar_offset)
        if rr_ar_temp._type == 1:
          # add to cache
          if acache.get(rr_ar_temp._dn) != None:
            acache.get(rr_ar_temp._dn).update_rtt(rr_ar_temp._ttl)  
          else:
            acache[rr_ar_temp._dn] = ACacheEntry(dict([InetAddr(inet_ntoa(rr_ns_temp._inaddr)),
                                        CacheEntry(expiration=rr_ar_temp._ttl,
                                                          authoritative=True))])
        rr_ar_offset += rr_ar_temp_len 
        

    # else if reply header answer count != 0 and stack.size() == 0
      # break
    # else if (if we are not making progress)
      # break  

    
        
  # Construct reply object 
  
  
  logger.log(DEBUG2, "our reply in full:") 
  logger.log(DEBUG2, hexdump(reply))

  ss.sendto(reply, address)
