# Whatsapp Discover

A tool for getting phone numbers of devices using Whatsapp by real time sniffing from an interface (disabled in this first version) or from a list of pcap files, which can be processed in batch

---

### Note 

Realtime sniffing and logfile has been added.


### Author

Deepak Daswani 

[@dipudaswani](http://twitter.com/dipudaswani)

[http://deepakdaswani.es](http://deepakdaswani.es)


### Fork

by [@xtr4nge](http://twitter.com/xtr4nge)

[https://github.com/xtr4nge/whatsapp_discover](https://github.com/xtr4nge/whatsapp_discover)


### Usage

	$ ./whatsapp_discover.pl -i interface | -f pcapfile[s] [-l logfile]

### Example

In the example below, the numbers have been darkened with X characters for privacy reasons

	deepak@kali:~/code/whatsapp_discover$ ./whatsapp_discover.pl -f /home/deepak/pcapfiles/*.cap
	
	Whatsapp Discover v1.0  --- Deepak Daswani (@dipudaswani) 2014
	                            http://deepakdaswani.es 
	
	Realtime sniffer  v1.0  --- Fork by xtr4nge (@xtr4nge) 2014
	                            https://github.com/xtr4nge/whatsapp_discover
	
	Parsing /home/deepak/pcapfiles/freewifi-01.cap ...
	Got 1 number! S.O: iPhone-2.11.4-5222 Mobile number: +1202XXXXXXX
	Parsing /home/deepak/pcapfiles/freewifi-02.cap ...
	Got 1 number! S.O: Android-2.11.152 Mobile number: +34616XXXXXX
	Got 1 number! S.O: Android-2.11.136 Mobile number: +34663XXXXXX
	Parsing /home/deepak/pcapfiles/freewifi-03.cap ...
	Got 1 number! S.O: BB-2.8.7345-443 Mobile number: +34695XXXXXX
	Parsing /home/deepak/pcapfiles/freewifi-04.cap ...
	Got 1 number! S.O: Symbian-2.11.173-443 Mobile number: +34660XXXXXX
	
	4 files parsed. 5 phone numbers using Whatsapp found...




