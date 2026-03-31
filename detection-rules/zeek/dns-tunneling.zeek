# Zeek DNS Tunneling Detection Signature
# Detects DNS queries longer than 60 characters and high entropy domains

module DNS_Tunneling;

export {
    redef enum Notice::Type += {
        Long_DNS_Query,
        High_Entropy_Domain
    };
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count) {
    
    # Detect DNS queries longer than 60 characters
    if ( |query| > 60 ) {
        NOTICE([$note=DNS_Tunneling::Long_DNS_Query,
                $msg=fmt("Long DNS query detected (%d chars): %s", |query|, query),
                $conn=c]);
    }
    
    # Detect high entropy domains (encoded data pattern)
    if ( |query| > 30 ) {
        local entropy = 0;
        for ( local i = 0; i < |query|; i++ ) {
            if ( query[i] ! in /[a-zA-Z0-9.-]/ ) {
                entropy += 1;
            }
        }
        if ( entropy / |query| > 0.3 ) {
            NOTICE([$note=DNS_Tunneling::High_Entropy_Domain,
                    $msg=fmt("High entropy DNS query detected: %s", query),
                    $conn=c]);
        }
    }
}
