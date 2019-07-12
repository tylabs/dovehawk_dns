# Settings for passive DNS
module dovehawk_dns;

export { 
	global APIKEY = "XXXX"; 

	global dns_report_url = "https://XXXX.amazonaws.com/default/XXX?feed=pdns&toolkey=" + APIKEY;

	## How often to report dns
	global logging_interval: interval = 16min &redef;

	#types of records to track
	global records: set[string] = {
		"A",
		"AAAA",
		"CNAME",
	} &redef;


}
