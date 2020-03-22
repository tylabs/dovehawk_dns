# Dovehawk.io pDNS Module v1.1.0 2020 03 21

@load base/utils/site
@load base/frameworks/sumstats
@load base/utils/directions-and-hosts
@load ../config


module dovehawk_dns;

export {


	## The log ID.
	redef enum Log::ID += { LOG };


	type Info: record {
		## Timestamp of when the data was finalized.
		ts:           time             &log;

		## Length of time that this Top measurement represents.
		ts_delta:     interval         &log;

		## The domain requested.
		query:  string &log;

		## The response.
		answer:   vector of string  &log;

	};

	global log_dns: event(rec: Info);
	global out: table[string] of vector of string;
	global send_json: function(json: string);
}

function send_json(json: string) {
    local post_data = json;

    local request: ActiveHTTP::Request = [
	$url=dovehawk_dns::dns_report_url,
	$method="POST",
	$client_data=post_data,
	$addl_curl_args = fmt("--header \"Content-Type: application/json\" --header \"Accept: application/json\""),
	$max_time = 3min
    ];
	
    when ( local resp = ActiveHTTP::request(request) ) {
		
		if (resp$code == 200) {
			print fmt("  Dovehawk pdns Reporting Sent ===> %s", resp$body);
		} else {
			print fmt("  Dovehawk pdns Reporting FAILED ===> %s", resp);
		}
		flush_all();
    }
	
}


event zeek_init() &priority=5
	{

	local rec: dovehawk_dns::Info;

	Log::create_stream(dovehawk_dns::LOG, [$columns=Info, $path="pdns", $ev=log_dns]);

	local r1 = SumStats::Reducer($stream="dns-unique", $apply=set(SumStats::UNIQUE));

	SumStats::create([$name="record-dns-unique",
	                  $epoch=dovehawk_dns::logging_interval,
	                  $reducers=set(r1),
	                  $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
	                  	{

	                  		local r = result["dns-unique"];
					local av1: vector of string = vector();
					for (i in r$unique_vals)
						{
							#print i$str;
							av1[|av1|] = i$str;

						}
					dovehawk_dns::out[key$str] = av1;

					#optional log file
	                  		Log::write(dovehawk_dns::LOG, [$ts=ts, $ts_delta=dovehawk_dns::logging_interval, $query=key$str,$answer = av1]);

	                  	},
  			   $epoch_finished(ts: time) =
                        	{
					#local av1: vector of string = vector();
					#av1[0] = "started";
					#Log::write(dovehawk_dns::LOG, [$ts=ts, $ts_delta=dovehawk_dns::logging_interval, $query="EPOCH",$answer = av1]);


					local c = |dovehawk_dns::out|;
					if (c > 0) {
						print fmt("Dovehawk %s: %d pdns records to send", ts, c);
						send_json(to_json(dovehawk_dns::out));
						#print to_json(dovehawk_dns::out);
					} else {
						print fmt("Dovehawk %s: no pdns records to send", ts);
					}

					#av1[0] = "finished";
					#Log::write(dovehawk_dns::LOG, [$ts=ts, $ts_delta=dovehawk_dns::logging_interval, $query="EPOCH",$answer = av1]);
					flush_all();
					# reset storage
					dovehawk_dns::out = table();
					
                        	}
	                 ]);

		print fmt("Dovehawk pDNS Reporting Period %s", dovehawk_dns::logging_interval);


	}





event DNS::log_dns(rec: DNS::Info)
	{
	
	if ( rec?$query && ! Site::is_local_name(rec$query) && rec?$qtype_name && rec$qtype_name in dovehawk_dns::records && strstr(rec$query, ".") != 0 && find_last(rec$query, /\.(.+)$/) != ".local")
		{
		#print fmt("%s", rec$query);
		if (rec?$answers) {
			for (i in rec$answers) {
				if (rec$answers[i] != rec$query) {
					#print "answer: " + rec$answers[i];
					SumStats::observe("dns-unique", [$str=rec$query], [$str=rec$answers[i]]);
				} 
			}
		} else {
			SumStats::observe("dns-unique", [$str=rec$query], [$str=""]);
			}

		}
	}

