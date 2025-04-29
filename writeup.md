<p>David Jara</p>
<p>April 28th, 2025</p>

<h1 style="text-align: center;">SEED Lab: Packet Sniffing</h1>

# Table of Contents

<ol type="I">
	<li><a href="#LINK">Link</a></li>
	<li><a href="#LINK">Link</a></li>
	<li><a href="#LINK">Link</a></li>
	<li><a href="#LINK">Link</a></li>
	<li><a href="#LINK">Link</a></li>
	<li><a href="#LINK">Link</a></li>
</ol>

# Task 2.1A: Understanding How a Sniffer Works

**Question 1:** Please use your own words to describe the sequence of the library calls that are essential for sniffer programs. This is meant to be a summary, not detailed explanation like the one in the tutorial or book.

> Answer goes here later...

**Question 2:** Why do you need the root privilege to run a sniffer program? Where does the program fail if it is executed without the root privilege?

> Root privilege is required due to operating system design. GNU/Linux (Ubuntu) is the operating system for which the packet sniffer binary was created, as such the spawned process is permitted to interact with hardware components (e.g. the Ethernet adapter) in accordance with the operating system's adjudication. When the program executes without root privilege, the program fails at the call to the function `pcap_open_live`, because it cannot "obtain a packet capture handle to capture packets on a device" ([source](https://www.tcpdump.org/manpages/pcap_open_live.3pcap.html)).
