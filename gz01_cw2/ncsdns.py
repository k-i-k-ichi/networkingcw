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

# This is a simple, single-threaded server that takes successive
# connections with each iteration of the following loop:
while 1:
  (data, address,) = ss.recvfrom(512) # DNS limits UDP msgs to 512 bytes
  if not data:
    log.error("client provided no data")
    continue
	

  print "Query received from client is:\n", hexdump(data)
	queryheader = Header.fromData(data)
	print "Query header received from client is:\n", hexdump(queryheader.pack()
  
  # Perform recursive lookup
    # If found in cache, assign value, return
    
    # If not, send query to other dns until found
			# Constructs an initial empty reply packet      
			# servername = b.root
      # add to stack (servername, querydomainname)
      
			# While stack contains query
				# pop from the stack
				# if servername found in cache
					# set answer section in reply object
					# TODO: handle CNAME
				# else
					# send query 
					# get return dns packet
					# If answer section count > 0
						# Add all entries of the section to cache			
					# If authority section count > 0, and not SOA ( deadend)
						# Add all pair with ( AR_sectionserverip, querydomain name) to stack
						# where AR_sectionserverip are dns server we got back from the query
						# querydomain name is the domainname of the query we just pop from stack				
												
						# If NS from authoritive section exist in glue record					
							# add all glue record in additional section to cache
				    # If NS not contains in cache or glue record

				  # If authority section count > 0, is a SOA.
						# Add SOA entry to authority section of the reply object

					# Else just skip to the next iteration of the loop
					
        
      # If Answer section count == 1, type = Cname
        # set queryname = CNAME
        # Query the same previous DNS
      # If Answer section count == 1, type = A
        # add key-pair value to cache
        # set TTL field returned from other dns server
        # construct return packet 
        # reply = 
        
      
      
  
  #
  # TODO: Insert code here to perform the recursive DNS lookup;
  #       putting the result in reply.
  #

  logger.log(DEBUG2, "our reply in full:") 
  logger.log(DEBUG2, hexdump(reply))

  ss.sendto(reply, address)
