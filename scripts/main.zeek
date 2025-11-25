module Amadey;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	redef enum Notice::Type += {
		## This notice is generated when a connection is potentially Amadey
		## malware C2.
		C2_Traffic_Observed,
	};

	## An option to enable detailed logs
	const enable_detailed_logs = T &redef;

	## Record type containing the column fields of the Amadey log.
	type Info: record {
		## Timestamp for when the activity happened.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;
		## The direction of this C2 data.
		is_orig: bool &log;
		## Signature based match when T.  When F this match comes from prior connection info.
		sig_match: bool &log;
		## The C2 data.
		payload: string &log;
	};

	## Default hook into Amadey logging.
	global log_amadey: event(rec: Info);

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## Indicator of Amadey C2.
	redef enum HTTP::Tags += { URI_Amadey_C2, };
}

redef record connection += {
	amadey: bool &default=F;
};

function amadey_detected(c: connection, is_orig: bool, data: string,
    sig_match: bool)
	{
	c$amadey = T;

	local msg = fmt("Potential Amadey C2 between source %s and dest %s (is_orig=%s) with payload in the sub field.",
	    c$id$orig_h, c$id$resp_h, is_orig);

	if ( sig_match )
		msg += "  Signature match.";
	else
		msg += "  Match from prior conn info.";

	if ( c?$http )
		# Add a tag to the http.log.
		add c$http$tags[URI_Amadey_C2];

	if ( enable_detailed_logs )
		{
		local info = Info($ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
		    $sig_match=sig_match, $payload=data);

		Log::write(Amadey::LOG, info);

		NOTICE([ $note=Amadey::C2_Traffic_Observed, $msg=msg, $sub=data, $conn=c,
		    $identifier=cat(c$id$orig_h, c$id$resp_h) ]);
		}
	else
		# Do not suppress notices.
		NOTICE([ $note=Amadey::C2_Traffic_Observed, $msg=msg, $sub=data, $conn=c ]);
	}

# Signature match function.
function amadey_match(state: signature_state, data: string): bool &is_used
	{
	amadey_detected(state$conn, state$is_orig, data, T);
	return T;
	}

# This detects other Amadey activity in the same connection.
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
	{
	# Detect when the response/request is built.
	if ( is_orig )
		return;

	if ( ! c$amadey )
		return;

	amadey_detected(c, is_orig, fmt("%s %s", c$http$method, c$http$uri), F);
	}

event zeek_init() &priority=5
	{
	if ( enable_detailed_logs )
		Log::create_stream(Amadey::LOG, [ $columns=Info, $ev=log_amadey,
		    $path="amadey", $policy=Amadey::log_policy ]);
	}
