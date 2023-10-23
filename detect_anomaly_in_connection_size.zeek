module training;

redef exit_only_after_terminate = T ;

global host_profiles: table [addr] of set[port] ;
global host_unique_ports: table [addr] of count ;
global remote_hosts: table [addr] of set[addr] ;
global max_bytes: table [addr] of int;
global min_bytes: table [addr] of int;
global resp_counter: table [addr] of count;

global histogram: table [addr,addr,port] of table [int] of count;
global histogram_resp: table [addr,port] of table [int] of count;

# First step: 
# 
# When a new connection is established
# we count all packages within 5 minutes
# after 5 minutes we reset all counters.
event connection_state_remove(c: connection)
{
	local orig=c$id$orig_h ;
	local resp=c$id$resp_h ;
	local service=c$id$resp_p ;
	#print fmt ("%s", c);

	if (resp !in resp_counter) {
		resp_counter[resp] = 0;
	}
	resp_counter[resp] += 1;

	local bytes_sent:int=100;
	bytes_sent=c$resp$num_bytes_ip;

	local byte_bit:int = 0;
	while (bytes_sent > 0) {
		byte_bit += 1;
		bytes_sent = bytes_sent / 2;
	}
	if ((resp !in max_bytes) || (byte_bit > max_bytes[resp])) {
		max_bytes[resp] = byte_bit;
	}
	if ((resp !in min_bytes) || (byte_bit < min_bytes[resp])) {
		min_bytes[resp] = byte_bit;
	}
	
	if ([orig,resp,service] !in histogram) {
		histogram[orig,resp,service] = set();
	}

	if ([resp,service] !in histogram_resp) {
		histogram_resp[resp,service] = set();
	}
	
	if (byte_bit !in histogram[orig,resp,service]) {
		histogram[orig,resp,service][byte_bit] = 0;
	}
	if (byte_bit !in histogram_resp[resp,service]) {
		histogram_resp[resp,service][byte_bit] = 0;
	}
	histogram[orig,resp,service][byte_bit] += 1;
	histogram_resp[resp,service][byte_bit] += 1;

}


event zeek_done()
{
	local iplist = "" ;

	#for ([orig,resp,service] in histogram)
	for ([resp,service] in histogram_resp)
	{
		print fmt ("--------------------------------");
		print fmt ("%s data transmissions to %s", resp_counter[resp], resp);

		local byte_bit:int = 0;
		local bytes:int = 1;
		local outlier:int = 0;
		while (byte_bit < max_bytes[resp] + 1) {
		
			while (byte_bit < min_bytes[resp]) {
				bytes = bytes * 2;
				byte_bit += 1;
			}
			
			
			local counter = 0;
			#if (byte_bit in histogram[orig,resp,service]) {
			#	counter = histogram[orig,resp,service][byte_bit];
			#}
			if (byte_bit in histogram_resp[resp,service]) {
				counter = histogram_resp[resp,service][byte_bit];
			}
			
			local outlier_msg:string = "";
			if ((outlier == 0) && (counter > 0)) {
				outlier = 2;
			}
			if ((outlier == 2) && (counter == 0)) {
				outlier = 1;
			}
			if (counter > 0) {
				outlier_msg = "<----";
				if (outlier == 1) {
					outlier_msg = "<+=+=+=";
				}
			}
			print fmt ("%s times < %s bytes %s", counter, bytes, outlier_msg);
			
			bytes = bytes * 2;
			byte_bit += 1;

		}
			
		
	}


}
