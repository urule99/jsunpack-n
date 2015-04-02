# jsunpack-n

jsunpack-n emulates browser functionality when visiting a URL. It's purpose is to detect exploits that target browser and browser plug-in vulnerabilities. It accepts many different types of input:

PDF files - samples/sample-pdf.file
Packet Captures - samples/sample-http-exploit.pcap
HTML files
JavaScript files
SWF files
This project contains the source code which runs at the website http://jsunpack.jeek.org/. Users can upload files, or enter script contents and URLs to decode. If you choose to install jsunpack-n on your own system, you can run it with the following command to fetch and decode a URL:

$ ./jsunpackn.py -u URL
Optionally, you can specify the -a option, which fetches further decoded URLs or paths. If you wish to decode a local file instead, you can simply run:

$ ./jsunpackn.py samples/sample-pdf.file
Other samples of malicious files exist within the samples directory.

One common problem running jsunpack-n is when there is no output. This means that there are no signature matches but it could mean that the file was decoded. You have the choice to use -v (verbose) or -V (veryverbose) to get more information in case jsunpack-n outputs nothing.


