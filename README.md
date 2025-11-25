# **Amadey Malware C2 Detection**

This Zeek package is designed to detect Command and Control (C2) traffic associated with the Amadey malware loader.

## **Resources and Context**

* **Blog Post:** [drkeithjones.com/index.php/2023/06/15/detecting-amadey-malware-with-zeek-zeek-roulette-2/](https://drkeithjones.com/index.php/2023/06/15/detecting-amadey-malware-with-zeek-zeek-roulette-2/)  
* **Video:** [youtube.com/live/AArPGeYdoNU?feature=share](https://youtube.com/live/AArPGeYdoNU?feature=share)

### **Update Log (November 2, 2023\)**

Detection logic was updated to account for new C2 samples. Relevant intelligence:

* [twitter.com/g0njxa/status/1719835010599952730?s=46\&t=6sVhWJG6mTIBgc\_qgCPzWQ](https://twitter.com/g0njxa/status/1719835010599952730?s=46&t=6sVhWJG6mTIBgc_qgCPzWQ)  
* [app.any.run/tasks/d46db0da-c4d1-466d-a294-136db798b80b/\#](https://app.any.run/tasks/d46db0da-c4d1-466d-a294-136db798b80b/#)

## **What This Package Detects**

This package focuses on identifying the unique communication patterns used by the Amadey malware family. Specifically, it detects:

1. **Amadey C2 Check-in/Heartbeat:** The initial and subsequent periodic HTTP POST requests sent by an infected host to the malicious C2 server. This traffic typically contains hardcoded fields and formatting specific to the malware variant.  
2. **C2 Artifact Delivery:** Further communication within the same connection that leads to the download of malicious payloads (e.g., DLL files like cred64.dll or clip64.dll).  
3. **HTTP Tagging:** It also adds a custom Amadey::URI\_Amadey\_C2 tag to the standard http.log for any request URI identified as being part of the C2 communication.

## **How This Package Detects It**

The detection logic is implemented using a combination of Zeek signatures and custom scripting:

1. **Zeek Signatures (amadey.sig):** The package uses regular expressions within Zeek signatures to look for specific patterns in the raw TCP payload that match known Amadey C2 communication formats.  
   * **Classic Amadey:** Signature patterns target HTTP POST requests containing specific URL-encoded parameters like id=...\&vs=...\&os=...\&pc=...\&un=....  
   * **Newer Amadey Variants:** A secondary signature targets recent variants that use a simpler payload, such as st=s.  
   * When a signature matches, the Amadey::amadey\_match function is called to log a notice.  
2. **Behavioral Detection (main.zeek):** Once a connection is marked as Amadey C2 via a signature match, the package tracks that connection. Subsequent HTTP transactions on the same connection are also flagged in the custom log and the notice log, even if they don't match the initial signature. This is achieved using the http\_message\_done event to detect related activity (like payload downloads).

## **The Benefits of Running This Package**

* **Early Detection:** Quickly identifies infected hosts attempting to communicate with known Amadey infrastructure before major damage occurs.  
* **Custom Logging:** Creates a dedicated amadey.log file (when detailed logging is enabled) which provides a concise, high-fidelity timeline of C2 activity, simplifying investigation.  
* **Contextual Correlation:** Tags related entries in the standard http.log, allowing analysts to easily pivot from the Amadey detection directly to the full HTTP transaction details, including downloaded file paths and response codes.  
* **Threat Intelligence:** Provides detection for multiple known C2 formats, including older and recently observed variants.

## **How to Install This Package**

This package can be installed using the Zeek Package Manager (zkg).

1. **Add the repository (if necessary):**  
   zkg refresh  
   \# If the package is in a custom repository, add it here. E.g.:  
   \# zkg add-community \# (If available)

2. **Install the package:**  
   zkg install amadey-detector-package-name \# Replace with actual package name

3. **Ensure it's loaded:** zkg automatically adds the package to your local site policy.

## **How to Use This Package**

The package automatically loads and begins detection when Zeek is run.

### **Running against a PCAP**

To run the package against a captured traffic file (.pcap):

zeek \-r traffic.pcap

### **Configuration**

By default, the package generates notices (in notice.log) but not the dedicated amadey.log. To enable the detailed custom log, you must redefine the global variable enable\_detailed\_logs in a local Zeek policy file (e.g., local.zeek).

1. **Create a local policy file** (e.g., local.zeek).  
2. **Add the redef:**  
   @load Amadey  
   redef Amadey::enable\_detailed\_logs \= T;

3. **Run Zeek**, ensuring your local policy is loaded:  
   zeek \-r traffic.pcap local.zeek

## **Example Output from This Package**

### **1\. Dedicated Amadey Log (amadey.log)**

This log contains the raw payload that triggered the detection, showing the initial C2 check-in and subsequent steps in the same connection.

\#separator 	  
\#set\_separator	,  
\#empty\_field	(empty)  
\#unset\_field	\-  
\#path	amadey  
\#open XXXXXXXX-XX-XX-XX-XX-XX  
\#fields	ts	uid	id.orig\_h	id.orig\_p	id.resp\_h	id.resp\_p	is\_orig	sig\_match	payload  
\#types	time	string	addr	port	addr	port	bool	bool	string  
1677699999.000000	C9rXSW3KSpTYvPrlI1	192.168.100.64	49200	212.113.119.255	80	T	T	POST /joomla/index.php HTTP/1.1\\x0d\\x0aContent-Type: application/x-www-form-urlencoded\\x0d\\x0aHost: 212.113.119.255\\x0d\\x0aContent-Length: 87\\x0d\\x0aCache-Control: no-cache\\x0d\\x0a\\x0d\\x0aid=896776584425\&vs=3.70\&sd=5d3738\&os=9\&bi=1\&ar=0\&pc=USER-PC\&un=admin\&dm=\&av=0\&lv=0\&og=1  
1677699999.000001	C9rXSW3KSpTYvPrlI1	192.168.100.64	49200	212.113.119.255	80	F	F	POST /joomla/index.php  
1677699999.000002	C9rXSW3KSpTYvPrlI1	192.168.100.64	49200	212.113.119.255	80	F	F	GET /joomla/Plugins/cred64.dll  
1677699999.000003	C9rXSW3KSpTYvPrlI1	192.168.100.64	49200	212.113.119.255	80	F	F	GET /joomla/Plugins/clip64.dll  
\#close XXXXXXXX-XX-XX-XX-XX-XX

### **2\. Notice Log (notice.log)**

This is the high-level alert generated by the package.

\#separator 	  
\#set\_separator	,  
\#empty\_field	(empty)  
\#unset\_field	\-  
\#path	notice  
\#open XXXXXXXX-XX-XX-XX-XX-XX  
\#fields	ts	uid	id.orig\_h	id.orig\_p	id.resp\_h	id.resp\_p	fuid	file\_mime\_type	file\_desc	proto	note	msg	sub	src	dst	p	n	peer\_descr	actions	email\_dest	suppress\_for	remote\_location.country\_code	remote\_location.region	remote\_location.city	remote\_location.latitude	remote\_location.longitude  
\#types	time	string	addr	port	addr	port	string	string	string	enum	enum	string	string	addr	addr	port	count	string	set\[enum\]	set\[string\]	interval	string	string	string	double	double  
1677699999.000000	C9rXSW3KSpTYvPrlI1	192.168.100.64	49200	212.113.119.255	80	\-	\-	\-	tcp	Amadey::C2\_Traffic\_Observed	Potential Amadey C2 between source 192.168.100.64 and dest 212.113.119.255 (is\_orig=T) with payload in the sub field.  Signature match.	POST /joomla/index.php HTTP/1.1\\x0d\\x0aContent-Type: application/x-www-form-urlencoded\\x0d\\x0aHost: 212.113.119.255\\x0d\\x0aContent-Length: 87\\x0d\\x0aCache-Control: no-cache\\x0d\\x0a\\x0d\\x0aid=896776584425\&vs=3.70\&sd=5d3738\&os=9\&bi=1\&ar=0\&pc=USER-PC\&un=admin\&dm=\&av=0\&lv=0\&og=1	192.168.100.64	212.113.119.255	80	\-	\-	Notice::ACTION\_LOG	(empty)	3600.000000	\-	\-	\-	\-	\-  
\#close XXXXXXXX-XX-XX-XX-XX-XX

## **What to do if this package identifies a detection on your network?**

A Notice::C2\_Traffic\_Observed detection for Amadey indicates a high probability that the source host is infected with the Amadey malware loader. This is a critical security event that requires immediate action.

**Immediate Actions:**

1. **Isolate the Host:** Immediately disconnect the internal source IP address (id.orig\_h in the logs, e.g., 192.168.100.64) from the network to prevent further compromise and lateral movement.  
2. **Gather Context:** Review the corresponding entries in the amadey.log and http.log using the uid to understand what files (e.g., cred64.dll, clip64.dll) were requested by the malware.  
3. **Perform Host Forensics:** Initiate forensic analysis on the isolated machine to confirm the infection, identify the initial infection vector, and look for secondary payloads dropped or executed by Amadey.

**Further Steps:**

* **Block C2 Domains/IPs:** Block the destination IP address (id.resp\_h, e.g., 212.113.119.255) and any associated domains at your network perimeter to prevent other potential infections from communicating.  
* **Malware Analysis:** Submit any downloaded payloads for dynamic or static analysis to confirm their functionality and identify new indicators of compromise (IOCs).  
* **Full Network Scan:** Conduct a full scan of your network environment to look for similar C2 traffic or other signs of infection.