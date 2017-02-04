# ATDScan

##### ATDScan10.py

A command-line scanner tool using ATD as a back-end. Works similar to VSE On-Demand Scanner.

ATD connection details and other behavior are configurable via ini file and/or CLI options.
Some options are only available in ini-file. CLI options override ini-file settings.

Examples:
* `ATDScan10.exe c:\temp`
* _This will submit all the files in the temp folder to ATD and save the scan log with the results._
* `ATDScan10.exe -x c:\ProgramData\Microsoft c:\Users\Val\Dropbox -q c:\atdquar -c 4 c:\ProgramData c:\Users\Val\`
* _This will scan all the files in ProgramData and User profile excluding Microsoft and Dropbox folders. All the files with severity 4 and above will be moved to quarantine c:\atdquar._
* `ATDScan10.exe -t 5 c:\ProgramData\*\*.exe c:\Users\Val\AppData\Roaming\*`
* _This will scan exe files in the ProgramData one-level nested folders and all files in Roaming folder and subfolders, using 5 scanning threads._


The tool uses [atdlib module](https://github.com/passimens/atdlib).

[Executable version](dist/ATDScan10.exe) is available in [dist](dist) folder.

[Sample ini file](dist/atdscan.ini.sample) is available in [dist](dist) folder.

##### Command line help

	usage: ATDScan10.exe [-h] [-x [path [path ...]]] [-a ATDHOST] [-u USERNAME]
											 [-p PASSWORD] [-t THREADS] [-r | -R] [-c CLEANAT]
											 [-q QUARDIR] [-s SCANLOG] [-d DRILLAT] [-i INCHSET]
											 path [path ...]

	ATD Scanner v.1.10. (c) Valeriy V. Filin, 2016. Scans files or folders
	submitting all the files to ATD and saving scan log. Bug reports, comments,
	suggestions are welcome at valerii.filin@gmail.com.

	positional arguments:
		path                  Path to target files or folders to be scanned
													(wildcards supported)

	optional arguments:
		-h, --help            show this help message and exit
		-x [path [path ...]], --exclude [path [path ...]]
													Path to files or folders to exclude (wildcards
													supported)
		-a ATDHOST, --atdhost ATDHOST
													ATD hostname or IP with optional port to use for file
													submission
		-u USERNAME, --username USERNAME
													ATD username to authenticate with
		-p PASSWORD, --password PASSWORD
													ATD user password to authenticate with
		-t THREADS, --threads THREADS
													Number of scanning threads
		-r, --reanalyze       Flag: force reanalyze file even if previously scanned
		-R, --no-reanalyze    Flag: no force reanalyze
		-c CLEANAT, --cleanat CLEANAT
													Severity threshold to quarantine the files (1-5). If
													not set - files are not quarantined
		-q QUARDIR, --quardir QUARDIR
													Quarantine folder receiving removed malicious files
		-s SCANLOG, --scanlog SCANLOG
													Path to ATD scan log
		-d DRILLAT, --drillat DRILLAT
													Severity threshold to provide drilldown logging for
													archives
		-i INCHSET, --inchset INCHSET
													Charset to use when decoding cmd line arguments

	Proxy along with optional username/password can be specified through
	HTTPS_PROXY environment variable: e.g.
	"HTTPS_PROXY=http://bob:P@ssw0rd@10.10.10.10:3128/" or
	"HTTPS_PROXY=http://10.20.20.20:8080".
