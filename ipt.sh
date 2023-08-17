#!/bin/bash

# ipset:
# * signed_on
# * permatrusted

# TSEQ: |54536f7572636520456e67696e65205175657279|

# Test count: -s <ME> ! match-set validated -j ACCEPT

PKT_A2S="54536f7572636520456e67696e65205175657279"
PKT_LOG="3030303030303030303000"

CMD_BASE="-t raw -p udp -i vmbr0"
CMD_COMMENT="-m comment --comment=srcds-hardening"
CMD_PORTS="-m multiport --dports 27000:29000"


ipset create permatrusted hash:ip      timeout 0 -! || true
ipset create  signed_on   hash:ip,port timeout 5 -! || true


# Log and DROP invalid packets
iptables -I PREROUTING 1 -t mangle -p all $CMD_COMMENT \
	-m state --state INVALID \
	-j LOG \
	-m limit --limit 2/min --log-ip-options --log-prefix "<|srcds-ipt|> INVALID PKT: "
	
iptables -I PREROUTING 2 -t mangle -p all $CMD_COMMENT \
	-m state --state INVALID \
	-j DROP

# data: TSEQ | hashlimit: srcip,dstport | limit: 6/min | j: DROP
iptables -I PREROUTING 1 $CMD_BASE $CMD_COMMENT $CMD_PORTS \
	-m string --algo bm --hex-string "|$PKT_A2S|" \
	-m hashlimit \
		--hashlimit-name tseq \
		--hashlimit-mode srcip,dstport \
		--hashlimit-above 6/min \
		--hashlimit-burst 8 \
	-j DROP

# data: TSEQ | limit: 20/sec | j: ACCEPT | else: DROP
iptables -I PREROUTING 2 $CMD_BASE $CMD_COMMENT $CMD_PORTS \
	-m string --algo bm --hex-string "|$PKT_A2S|" \
	-m limit --limit 20/sec --limit-burst 50 \
	-j ACCEPT

iptables -I PREROUTING 3 $CMD_BASE $CMD_COMMENT $CMD_PORTS \
	-m string --algo bm --hex-string "|$PKT_A2S|" \
	-j DROP
	

# Log flair signon and add to signed_on set
iptables -I PREROUTING 4 $CMD_BASE $CMD_COMMENT $CMD_PORTS \
	-m string --algo bm --hex-string "|$PKT_LOG|" \
	-m length --length 48 --from 26 --to 48 \
	-j LOG \
	-m limit --limit 250/min --log-ip-options --log-level error --log-prefix "<|srcds-ipt|> signon: "

iptables -I PREROUTING 5 $CMD_BASE $CMD_COMMENT $CMD_PORTS \
	-m string --algo bm --hex-string "|$PKT_LOG|" \
	-m length --length 48 --from 26 --to 48 \
	-j SET --add-set signed_on src,dst --timeout 5


# Log and DROP small packets
iptables -I PREROUTING 6 $CMD_BASE $CMD_COMMENT $CMD_PORTS \
	-m length --length 0:32 \
	-j LOG \
	-m limit --limit 2/min --log-ip-options --log-prefix "<|srcds-ipt|> len < 32: "

iptables -I PREROUTING 7 $CMD_BASE $CMD_COMMENT $CMD_PORTS \
	-m length --length 0:32 \
	-j DROP


# Log and DROP bigass packets
iptables -I PREROUTING 8 $CMD_BASE $CMD_COMMENT $CMD_PORTS \
	-m length --length 2521:65535 \
	-j LOG \
	-m limit --limit 2/min --log-ip-options --log-prefix "<|srcds-ipt|> len > 2521: "

iptables -I PREROUTING 9 $CMD_BASE $CMD_COMMENT $CMD_PORTS \
	-m length --length 2521:65535 \
	-j DROP


# Rate limit permatrusted (ACCEPT should be removed)
iptables -I PREROUTING 10 $CMD_BASE $CMD_COMMENT \
	-m set --match-set permatrusted src \
	-m hashlimit \
		--hashlimit-name validated_speedlimit \
		--hashlimit-mode srcip,dstport \
		--hashlimit-above 72/sec \
		--hashlimit-burst 80 \
	-j DROP

iptables -I PREROUTING 11 $CMD_BASE $CMD_COMMENT \
	-m set --match-set permatrusted src \
	-j ACCEPT


# Rate limit flair loged (should be replaced with a very strict burst)
iptables -I PREROUTING 12 $CMD_BASE $CMD_COMMENT \
	-m set --match-set signed_on src,dst \
	-m hashlimit \
		--hashlimit-name signedon_speedlimit \
		--hashlimit-mode srcip,dstport \
		--hashlimit-above 18/sec \
		--hashlimit-burst 20 \
	-j DROP

iptables -I PREROUTING 13 $CMD_BASE $CMD_COMMENT \
	-m set --match-set signed_on src,dst \
	-j ACCEPT


# Not loged udp spam limit
iptables -I PREROUTING 14 $CMD_BASE $CMD_COMMENT $CMD_PORTS \
	-m hashlimit \
		--hashlimit-name speedlimit \
		--hashlimit-mode srcip,dstport \
		--hashlimit-above 7/sec \
		--hashlimit-burst 9 \
	-m set ! --match-set permatrusted src \
	-m set ! --match-set signed_on src,dst \
	-j LOG \
	-m limit --limit 2/min --log-ip-options --log-prefix "<|srcds-ipt|> udp spam: "
 
iptables -I PREROUTING 15 $CMD_BASE $CMD_COMMENT $CMD_PORTS \
	-m hashlimit \
		--hashlimit-name speedlimit \
		--hashlimit-mode srcip,dstport \
		--hashlimit-above 7/sec \
		--hashlimit-burst 9 \
	-m set ! --match-set permatrusted src \
	-m set ! --match-set signed_on src,dst \
	-j DROP


