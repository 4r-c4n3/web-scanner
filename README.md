**Web Scanner Tool**
=====================
**Overview**
-----------
The Web Scanner Tool is a command-line utility for scanning web applications for security vulnerabilities. It provides various options for scanning open ports, testing HTTP methods, and checking for other bugs.
**Usage**
-----
python3 web-scanner.py TARGET [OPTIONS]
Replace `TARGET` with the URL or domain name of the web application you want to scan.
**Options**
--------
* -p, --ports: Scan for open ports
* -hm, --http-methods: Test various HTTP methods
* -o, --other: Check for other bugs
* -f, --full: Run all security checks
* --help: Show this message and exit.
**Examples**
---------
* Scan a web application for open ports:
python3 web-scanner.py -p kfueit.edu.pk
* Test various HTTP methods on a web application:
python3 web-scanner.py -hm kfueit.edu.pk
* Run a full security scan on a web application:
python3 web-scanner.py -f kfueit.edu.pk
**Note**
----
This tool is for educational purposes only and should not be used without permission from the target web application's owner.
