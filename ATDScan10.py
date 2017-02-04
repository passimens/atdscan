import codecs
import ConfigParser
import argparse
import atdlib
from atdlib import *
import socket
import sys
import hashlib
import os
import glob
import time
import logging
import Queue
import threading
import fnmatch

global mylog

def md5(fname):
    hash = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash.update(chunk)
    return hash.hexdigest()

def filegen(root):
	if os.path.isfile(root): yield root
	elif os.path.isdir(root):
		for (r, d, f) in os.walk(root):
			for file in f: yield os.path.join(r, file)
	else:
		pass

def globfilegen(path):
	for p in glob.iglob(path):
		for f in filegen(p):
			yield f


class FileFilter:

	def __init__(self, minsize, maxsize, incltypes, excltypes, exclpaths):
		self._minsize = minsize
		self._maxsize = maxsize
		self._incltypes = incltypes.split(',') if incltypes else []
		self._excltypes = excltypes.split(',') if excltypes else []
		self._exclpaths = exclpaths
	
	def test(self, file):
		
		# filter by size
		try:
			filesize = os.path.getsize(file)
		except os.error:
			mylog.error(u'Failed to determine the size of file "{0}".'.format(file))
			return False
		if self._minsize and filesize < self._minsize:
			return False
		if self._maxsize and filesize > self._maxsize:
			return False
		
		# filter by extension
		fileext = os.path.splitext(file)[1][1:]
		if self._incltypes:
			if not fileext or fileext not in self._incltypes:
				return False
		if self._excltypes:
			if fileext and fileext in self._excltypes:
				return False

		# filter by exclsions
		if self._exclpaths:
			# Normalize file path
			absfile = os.path.abspath(os.path.expandvars(os.path.expanduser(file)))
			for exclitem in self._exclpaths:
				# if exclusion is a wildcard (widest case)
				if fnmatch.fnmatch(file, exclitem): return False
				# Normalize exclusion path
				absexcl = os.path.abspath(os.path.expandvars(os.path.expanduser(exclitem)))
				# if exclusion is a file or folder name
				if os.path.commonprefix([absfile, absexcl]) == absexcl: return False
				# if exclusion is a wildcard
				if fnmatch.fnmatch(absfile, absexcl): return False
				
		return True
	

class scanner:

	def __init__(self, atd, threads, reanalyze, cleanat, quardir, scanlog, drillat):
	
		self._atd = atd
		self._threads = threads
		self._reanalyze = reanalyze
		self._cleanat = cleanat
		self._quardir = quardir
		self._drillat = drillat
		
		self._workers = []
		self._terminate = threading.Event()
		self._stopWork = threading.Event()
		self._endOfWork = threading.Event()
		
		self._countersTotal = 0;
		self._countersSev = {};
		self._countersQtned = 0;
		self._countersError = 0;
		self._logQtned = [];
		self._logFailed = [];
		
		# --- Initialize scan logger: ---
		scanLogger = logging.getLogger('scanlog')
		logFormat = logging.Formatter('%(name)s: %(message)s')
		if scanlog:
			try:
				logHandler = logging.FileHandler(scanlog, mode='w')
			except:
				mylog.error(u'Failed to open log file "{0}". Writing to stdout...'.format(scanlog))
				logHandler = logging.StreamHandler(sys.stdout)
		else:
			logHandler = logging.StreamHandler(sys.stdout)
		logHandler.setFormatter(logFormat)
		scanLogger.addHandler(logHandler)
		scanLogger.setLevel(logging.INFO)
		self._slogger = scanLogger
		
		# --- Initialize scanning queue: ---
		self._scanQueue = Queue.Queue()

		# Spawn scanning threads
		for i in range(self._threads):
			t = threading.Thread(target=self._process, args=(i,))
			t.daemon = False
			t.start()
			self._workers.append(t)
	 
		self._slogger.info(u' ============ Scanner initialized at: {0} ============ '.format(time.ctime()))
		
		
	def scan(self, file):
		self._scanQueue.put(file)

		
	def finish(self):
		#Instructs scanning threads to stop right after detecting queue empty
		self._endOfWork.set()
		
		# Wait for scanning threads to complete their current jobs
		stop = False

		while not stop:
			stop = True
			for t in self._workers:
				t.join(0.1)
				if t.is_alive():
					stop = False
					time.sleep(1)
					break
			
		self._slogger.info(u' --------------------- Scan Statistics ---------------------- ')
		self._slogger.info(u'Total files scanned: {0}'.format(self._countersTotal))
		keys = sorted(self._countersSev.keys())
		for i in keys:
			self._slogger.info(u' - Severity {0} files: {1}'.format(i, self._countersSev[i]))
		self._slogger.info(u'')
		self._slogger.info(u'Quarantined files: {0}'.format(self._countersQtned))
		self._slogger.info(u'Files with errors: {0}'.format(self._countersError))
		self._slogger.info(u'')
		if self._countersQtned:
			self._slogger.info(u' --------------------- Quarantined Files ---------------------- ')
			self._slogger.info('\n\t'.join(self._logQtned))
			self._slogger.info(u'')
		if self._countersError:
			self._slogger.info(u' --------------------- Files with Errors ---------------------- ')
			self._slogger.info('\n\t'.join(self._logFailed))
			self._slogger.info(u'')
		self._slogger.info(u' ============ Scan finished at: {0} ============ '.format(time.ctime()))
		

	def stopwork(self):
		#Instructs scanning threads to stop immediately after current item
		self._stopWork.set()
		mylog.info(u'Sent global stop event to all scanning threads.')
		mylog.info(u'Waiting for the threads to exit after respective current items...')
		self.finish()
		
	
	def terminate(self):
		#Instructs scanning threads to stop immediately without waiting
		self._terminate.set()
		mylog.info(u'Sent global terminate event to all scanning threads.')
		mylog.info(u'The threads are to stop immediately...')
		self.finish()
		
	
	def _process(self, id):

		while not self._stopWork.is_set():
		
			try:
		
				logrecord = []
			
				try:
					# Get next item. Wait for 0.1s at most
					file = self._scanQueue.get(True, 0.1)
				except Queue.Empty:
					if self._endOfWork.is_set():
						# The caller indicated end of work, and no items left in the queue.
						mylog.info(u'Scan queue is empty. End-of-work signal received. Thread #{0} exiting...'.format(id))
						return
					else:
						# The caller is still submitting jobs to the queue. Waiting...
						continue
				
				mylog.info(u'Scan thread #{0} processing file "{1}"'.format(id, file))
				self._countersTotal += 1;
				
				if not self._reanalyze :
					# --- Check if file was previously analyzed. Submit if not: ---
					try:
						md5s = md5(file)
					except:
						logrecord.append(u'!{0}: Failed to calculate MD5 sum'.format(file))
						mylog.error(u'{0}: Failed to calculate MD5 sum'.format(file))
						raise
						#return

					try:
						dStatus = self._atd.md5status(md5h=md5s)
					except ATDError as e:
						logrecord.append(u'!{0}: Failed to get MD5 status from ATD'.format(file))
						mylog.error(u'{0}: Failed to get MD5 status from ATD'.format(file))
						raise
						#return
					
					if dStatus['status'] in (0, 6, 7, 8):
						# No previous submissions, or cancelled (6), or invalid(7), or discarded(8)
						try:
							myip = socket.gethostbyname(socket.gethostname())
						except:
							mylog.warn(u'Error getting local IP address. Using blank')
							#raise
							myip = ''

						try:
							jobid = self._atd.fileup(file, myip)
						except ATDError as e:
							logrecord.append(u'!{0}: Failed to upload file to ATD'.format(file))
							mylog.error(u'{0}: Failed to upload file to ATD'.format(file))
							raise
							#return
						except IOError as e:
							logrecord.append(u'!{0}: Failed to open file for upload'.format(file))
							mylog.error(u'{0}: Failed to open file for upload'.format(file))
							raise
							#return

						status = 0

					elif 0 < dStatus['status'] <= 5 :
						jobid = dStatus['jobid']
						status = dStatus['status']

					else:
						logrecord.append(u'!{0}: atdstatus returned unexpected result: {1}'.format(file, dStatus['status']))
						mylog.error(u'{0}: atdstatus returned unexpected result: {1}'.format(file, dStatus['status']))
						raise ATDError

				else :
					# --- User chose reanalyze = yes. Submit the file ignoring previous results: ---
					
					try:
						myip = socket.gethostbyname(socket.gethostname())
					except:
						mylog.warn(u'Error getting local IP address. Using blank')
						myip = ''

					try:
						jobid = self._atd.fileup(file, myip, True)
					except ATDError as e:
						logrecord.append(u'!{0}: Failed to upload file to ATD'.format(file))
						mylog.error(u'{0}: Failed to upload file to ATD'.format(file))
						raise
						#return
					except IOError as e:
						logrecord.append(u'!{0}: Failed to open file for upload'.format(file))
						mylog.error(u'{0}: Failed to open file for upload'.format(file))
						raise
					
					status = 0

				# --- Wait for file analysis to complete: ---

				while status in (0, 2, 3) :

					if self._terminate.is_set():
						logrecord.append(u'!{0}: Scanning thread was terminated, no result received'.format(file))
						mylog.error(u'{0}: Scanning thread was terminated, no result received'.format(file))
						raise Exception
					
					time.sleep(5)
					try:
						dStatus = self._atd.jobstatus(jobid=jobid)
					except ATDError as e:
						logrecord.append(u'!{0}: Failed to get job status'.format(file))
						mylog.error(u'{0}: Failed to get job status'.format(file))
						raise
						#return
					
					status = dStatus['status']

				# --- Analysis completed. Verify is completed successfully: ---
				if status != 5 :
					logrecord.append(u'!{0}: Job status is invalid'.format(file))
					mylog.error(u'{0}: Job status is invalid'.format(file))
					raise ATDError

				# --- Saving results to log file: ---
				severity = dStatus['severity']
				
				if not severity in self._countersSev:
					self._countersSev[severity] = 1
				else:
					self._countersSev[severity] += 1
				
				# React and log
				if self._cleanat and severity >= self._cleanat and os.path.isdir(self._quardir):
					
					# move file to quarantine
					usfname = os.path.split(file)[1]
					md5s = md5(file)
					uqfpath = os.path.join(self._quardir, usfname + "." + md5s[:8])
					if os.path.isfile(uqfpath): os.remove(uqfpath)
					os.rename(file, uqfpath)
					
					logrecord.append(u'{0} => score: {1} => quarantined'.format(file, severity))
					self._logQtned.append(file)
					self._countersQtned += 1
				
				else:
					logrecord.append(u'{0} => score: {1} => skipped'.format(file, severity))
				
				# Log composite sample details
				if severity > self._drillat:
					
					#get taskidlist
					try:
						lTasks = self._atd.jobtasks(jobid)
					except ATDError as e:
						logrecord.append(u'!{0}: Failed to get job tasks'.format(file))
						mylog.error(u'{0}: Failed to get job tasks'.format(file))
						raise
						#return

					if len(lTasks) > 1:
						
						#get bulksamplestatus for taskids
						try:
							dBStat = self._atd.bulkstatus(tasks = lTasks)
						except ATDError as e:
							logrecord.append(u'!{0}: Failed to get bulkstatus'.format(file))
							mylog.error(u'{0}: Failed to get bulkstatus'.format(file))
							raise
							#return
						
						for st in dBStat:
						
							try:
								score = st['score']
								taskid = st['taskID']
							except KeyError as e:
								logrecord.append(u'!{0}: Failed to parse response data'.format(file))
								mylog.error(u'{0}: Failed to parse response data'.format(file))
								raise
								#return
								
							if score > self._drillat:
								try:
									report = self._atd.taskreport(taskid, 'json')
								except ATDError as e:
									logrecord.append(u'!{0}: Failed to get task report'.format(file))
									mylog.error(u'{0}: Failed to get task report'.format(file))
									raise
									#return
								
								try:
									jdata = json.loads(report)
									infile = jdata['Summary']['Subject']['Name']
									insev = score
								except (ValueError, KeyError) as e:
									logrecord.append(u'!{0}: Failed to parse report content'.format(file))
									mylog.error(u'{0}: Failed to parse report content'.format(file))
									raise
									#return
									
								logrecord.append(u'         \--- {0} => score: {1}'.format(infile, insev))
						
					else:
						pass

			except:
				self._logFailed.append(file) # put error file name to final report
				self._countersError += 1; # increment error counter for report
			finally:
				if logrecord: self._slogger.info('\n'.join(logrecord))


# =================== Main Script Body =====================

if __name__ == '__main__':

	logFormat = logging.Formatter('%(asctime)s:%(levelname)s:%(name)s:%(message)s')
	logHandler = logging.StreamHandler()
	logHandler.setFormatter(logFormat)
	mylog = logging.getLogger('atdscan')
	mylog.addHandler(logHandler)
	mylog.setLevel(logging.INFO)

	cfgfile = 'atdscan.ini'

	# -- Default init values --
	config = ConfigParser.SafeConfigParser()

	config.add_section('connection')
	config.set('connection', 'atdhost', '')
	config.set('connection', 'username', '')
	config.set('connection', 'password', '')
	config.set('connection', 'usessl', 'True')
	config.add_section('scanning')
	config.set('scanning', 'threads', '10')
	config.set('scanning', 'reanalyze', 'False')
	config.set('scanning', 'cleanat', '0')
	config.set('scanning', 'quardir', '')
	config.set('scanning', 'minsize', '100')
	config.set('scanning', 'maxsize', '50000000')
	config.set('scanning', 'incltypes', '')
	config.set('scanning', 'excltypes', '')
	config.set('scanning', 'exclpaths', '')
	config.add_section('reporting')
	config.set('reporting', 'scanlog', '')
	config.set('reporting', 'drillat', '3')
	#config.set('reporting', 'loglevel', 'error')
	config.add_section('cmdline')
	config.set('cmdline', 'inchset', 'utf-8')
	#config.set('cmdline', 'outchset', 'utf-8')
	# -- ------------------- --

	# -- Parse config file parameters --
	if os.path.isfile(cfgfile):
		config.read(cfgfile)
	else:
		config.read(os.path.join(os.path.split(sys.argv[0])[0], cfgfile))

	atdhost = config.get('connection', 'atdhost')
	username = config.get('connection', 'username')
	password = config.get('connection', 'password')
	usessl = config.getboolean('connection', 'usessl')
	threads = config.getint('scanning', 'threads')
	reanalyze = config.getboolean('scanning', 'reanalyze')
	cleanat = config.getint('scanning', 'cleanat')
	quardir = config.get('scanning', 'quardir')
	minsize = config.getint('scanning', 'minsize')
	maxsize = config.getint('scanning', 'maxsize')
	incltypes = config.get('scanning', 'incltypes')
	excltypes = config.get('scanning', 'excltypes')
	exclpaths = config.get('scanning', 'exclpaths')
	scanlog = config.get('reporting', 'scanlog')
	drillat = config.getint('reporting', 'drillat')
	#loglevel = config.get('reporting', 'loglevel')
	inchset = config.get('cmdline', 'inchset')
	#outchset = config.get('cmdline', 'outchset')
	
	if exclpaths:
		#exclpaths = unicode(exclpaths, 'utf-8').encode(sys.getfilesystemencoding()).split('\n')
		uexclpaths = unicode(exclpaths, 'utf-8').split(u'\n')
	else :
		uexclpaths = []
	# -- ---------------------------- --

	# -- Parse command line parameters --
	parser = argparse.ArgumentParser(
		description='''
			ATD Scanner v.1.10. (c) Valeriy V. Filin, 2016.
			Scans files or folders submitting all the files to ATD and saving scan log.
			Bug reports, comments, suggestions are welcome at valerii.filin@gmail.com.
		''',
		epilog='Proxy along with optional username/password can be specified through HTTPS_PROXY environment variable: e.g. "HTTPS_PROXY=http://bob:P@ssw0rd@10.10.10.10:3128/" or "HTTPS_PROXY=http://10.20.20.20:8080".'
		#formatter_class=argparse.RawTextHelpFormatter
		)
	parser.add_argument('targets', metavar='path', nargs='+', help='Path to target files or folders to be scanned (wildcards supported)')
	parser.add_argument('-x', '--exclude', metavar='path', nargs='*', help='Path to files or folders to exclude (wildcards supported)')
	parser.add_argument('-a', '--atdhost', required=True if not atdhost else False, help='ATD hostname or IP with optional port to use for file submission')
	parser.add_argument('-u', '--username', required=True if not username else False, help='ATD username to authenticate with')
	parser.add_argument('-p', '--password', required=True if not password else False, help='ATD user password to authenticate with')
	parser.add_argument('-t', '--threads', type=int, help='Number of scanning threads')
	xgroup = parser.add_mutually_exclusive_group()
	xgroup.add_argument('-r', '--reanalyze', dest='reanalyze', action='store_true', help='Flag: force reanalyze file even if previously scanned')
	xgroup.add_argument('-R', '--no-reanalyze', dest='reanalyze', action='store_false', help='Flag: no force reanalyze')
	parser.add_argument('-c', '--cleanat', type=int, help='Severity threshold to quarantine the files (1-5). If not set - files are not quarantined')
	parser.add_argument('-q', '--quardir', help='Quarantine folder receiving removed malicious files')
	parser.add_argument('-s', '--scanlog', help='Path to ATD scan log')
	parser.add_argument('-d', '--drillat', type=int, help='Severity threshold to provide drilldown logging for archives')
	#parser.add_argument('-l', '--loglevel', choices = ['critical', 'error', 'warning', 'info', 'debug', 'notset'], help='Log level for operational information')
	parser.add_argument('-i', '--inchset', help='Charset to use when decoding cmd line arguments')
	#parser.add_argument('-o', '--outchset', help='Charset to use for stdout')

	args = parser.parse_args()

	targets = args.targets
	exclude = args.exclude if args.exclude != None else []
	atdhost = args.atdhost if args.atdhost else atdhost
	username = args.username if args.username else username
	password = args.password if args.password else password
	threads = args.threads if args.threads else threads
	reanalyze = args.reanalyze if args.reanalyze != None else reanalyze
	cleanat = args.cleanat if args.cleanat != None else cleanat
	quardir = args.quardir if args.quardir != None else quardir
	scanlog = args.scanlog if args.scanlog != None else scanlog
	drillat = args.drillat if args.drillat != None else drillat
	#loglevel = args.loglevel if args.loglevel else loglevel
	inchset = args.inchset if args.inchset else inchset
	#outchset = args.outchset if args.outchset else outchset
	# -- ----------------------------- --

	try:
		utargets = [unicode(t, inchset) for t in targets]
		uexclude = [unicode(t, inchset) for t in exclude]
		uqtndir = unicode(quardir, inchset)
		uscnlog = unicode(scanlog, inchset)
	except:
		mylog.error(u'Invalid charset selected: {0}'.format(inchset))
		sys.exit(1)

	if uexclude: uexclpaths += uexclude
	#if exclude: exclpaths += exclude
	if uqtndir: uexclpaths.append(uqtndir)
	#if quardir: exclpaths.append(quardir)
	#print 'uexclpaths = ', uexclpaths
	#utfexcl = [t.encode('utf-8') for t in exclpaths]
		
	if cleanat > 0 and uqtndir and (not os.path.exists(uqtndir) or not os.path.isdir(uqtndir)):
		try:
			os.mkdir(uqtndir)
		except:
			mylog.error(u'Failed to create quarantine dir {0}'.format(uqtndir))
			sys.exit(1)
			
	# ------ Scan target through ATD: ------

	# --- Init ATD session: ---

	atd = atdlib.atdsession(ssl=True, uag='ATD Scanner v.1.10')

	# --- Authenticate to ATD box: ---
	try:
		res = atd.open(atdhost, username, password)
	except:
		mylog.error(u'Failed to connect to ATD {0}.'.format(atdhost))
		sys.exit(1)
		

	# --- Init Scanner object: ---
	sc = scanner(
		atd = atd,
		threads = threads,
		reanalyze = reanalyze,
		cleanat = cleanat,
		quardir = uqtndir,
		scanlog = uscnlog,
		drillat = drillat
	)
	
	filefilter = FileFilter(minsize, maxsize, incltypes, excltypes, uexclpaths)

	try:
	
		# Feed scanner with scan jobs
		for t in utargets:
			for file in globfilegen(t):
				if filefilter.test(file):
					sc.scan(file)

		# Wait for the scanner to finish
		sc.finish()
		
	except KeyboardInterrupt as e:
		mylog.error(u'User sent KeyboardInterrupt event.')
		try:
			sc.stopwork()
		except KeyboardInterrupt as ee:
			mylog.error(u'User sent repeated KeyboardInterrupt event.')
			sc.terminate()

	# --- Close ATD session: ---
	try:
		res = atd.close()
	except:
		mylog.error(u'Failed to close ATD session.')
		sys.exit(1)