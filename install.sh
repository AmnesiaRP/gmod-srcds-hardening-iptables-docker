#!/bin/bash

# ipset:
# * signed_on
# * permatrusted

PKT_A2S="54536f7572636520456e67696e65205175657279"
PKT_LOG="3030303030303030303000"

CMD_BASE="-t raw -p udp -i vmbr0"
CMD_COMMENT="-m comment --comment=srcds-hardening"
CMD_PORTS="-m multiport --dports 27000:29000"


ipset create blacklist    hash:ip      timeout 0 -! || true
ipset create permatrusted hash:ip      timeout 0 -! || true
ipset create signed_on    hash:ip,port timeout 2 -! || true


# Log and DROP invalid packets
iptables -I PREROUTING 1 -t mangle -p all $CMD_COMMENT \
	-m state --state INVALID \
	-j LOG \
	-m limit --limit 2/min --log-ip-options --log-prefix "<|srcds-ipt|> INVALID PKT: "

iptables -I PREROUTING 2 -t mangle -p all $CMD_COMMENT \
	-m state --state INVALID \
	-j DROP


# Blacklist
iptables -I PREROUTING 1 $CMD_BASE $CMD_COMMENT \
  -m set --match-set blacklist src \
  -j DROP


# data: A2S | hashlimit: srcip,dstport | limit: 8/min | j: LOG & DROP
iptables -I PREROUTING 2 $CMD_BASE $CMD_COMMENT $CMD_PORTS \
	-m string --algo bm --hex-string "|$PKT_A2S|" \
	-m hashlimit \
		--hashlimit-name tseq \
		--hashlimit-mode srcip,dstport \
		--hashlimit-above 8/min \
		--hashlimit-burst 10 \
	-j LOG \
	-m limit --limit 120/min --log-ip-options --log-level error --log-prefix "<|srcds-ipt|> A2S DoS: "
 
iptables -I PREROUTING 3 $CMD_BASE $CMD_COMMENT $CMD_PORTS \
	-m string --algo bm --hex-string "|$PKT_A2S|" \
	-m hashlimit \
		--hashlimit-name tseq \
		--hashlimit-mode srcip,dstport \
		--hashlimit-above 10/min \
		--hashlimit-burst 20 \
	-j DROP


# data: A2S | limit: 20/sec | j: ACCEPT | else: LOG & DROP
iptables -I PREROUTING 4 $CMD_BASE $CMD_COMMENT $CMD_PORTS \
	-m string --algo bm --hex-string "|$PKT_A2S|" \
	-m limit --limit 30/sec --limit-burst 60 \
	-j ACCEPT

iptables -I PREROUTING 5 $CMD_BASE $CMD_COMMENT $CMD_PORTS \
	-m string --algo bm --hex-string "|$PKT_A2S|" \
	-j LOG \
	-m limit --limit 1/sec --log-ip-options --log-level error --log-prefix "<|srcds-ipt|> A2S DDoS: "

iptables -I PREROUTING 6 $CMD_BASE $CMD_COMMENT $CMD_PORTS \
	-m string --algo bm --hex-string "|$PKT_A2S|" \
	-j DROP


# Log flair signon and add to signed_on set
iptables -I PREROUTING 7 $CMD_BASE $CMD_COMMENT $CMD_PORTS \
	-m string --algo bm --hex-string "|$PKT_LOG|" \
	-m length --length 48 --from 26 --to 48 \
	-j LOG \
	-m limit --limit 250/min --log-ip-options --log-level error --log-prefix "<|srcds-ipt|> signon: "

iptables -I PREROUTING 8 $CMD_BASE $CMD_COMMENT $CMD_PORTS \
	-m string --algo bm --hex-string "|$PKT_LOG|" \
	-m length --length 48 --from 26 --to 48 \
	-j SET --add-set signed_on src,dst --timeout 2


# Log and DROP small packets
iptables -I PREROUTING 9 $CMD_BASE $CMD_COMMENT $CMD_PORTS \
	-m length --length 0:32 \
	-j LOG \
	-m limit --limit 2/min --log-ip-options --log-prefix "<|srcds-ipt|> len < 32: "

iptables -I PREROUTING 10 $CMD_BASE $CMD_COMMENT $CMD_PORTS \
	-m length --length 0:32 \
	-j DROP


# Log and DROP bigass packets
iptables -I PREROUTING 11 $CMD_BASE $CMD_COMMENT $CMD_PORTS \
	-m length --length 2521:65535 \
	-j LOG \
	-m limit --limit 2/min --log-ip-options --log-prefix "<|srcds-ipt|> len > 2521: "

iptables -I PREROUTING 12 $CMD_BASE $CMD_COMMENT $CMD_PORTS \
	-m length --length 2521:65535 \
	-j DROP


# Rate limit permatrusted
iptables -I PREROUTING 13 $CMD_BASE $CMD_COMMENT $CMD_PORTS \
	-m set --match-set permatrusted src \
	-m hashlimit \
		--hashlimit-name validated_speedlimit \
		--hashlimit-mode srcip,dstport \
		--hashlimit-above 50/sec \
		--hashlimit-burst 54 \
	-j LOG \
	-m limit --limit 1/sec --log-ip-options --log-prefix "<|srcds-ipt|> permatrusted flood: "

iptables -I PREROUTING 14 $CMD_BASE $CMD_COMMENT $CMD_PORTS \
	-m set --match-set permatrusted src \
	-m hashlimit \
		--hashlimit-name validated_speedlimit \
		--hashlimit-mode srcip,dstport \
		--hashlimit-above 50/sec \
		--hashlimit-burst 54 \
	-j DROP


# Rate limit flair loged (should be replaced with a very strict burst)
iptables -I PREROUTING 15 $CMD_BASE $CMD_COMMENT $CMD_PORTS \
	-m set --match-set signed_on src,dst \
	-m set ! --match-set permatrusted src \
	-m hashlimit \
		--hashlimit-name signedon_speedlimit \
		--hashlimit-mode srcip,dstport \
		--hashlimit-above 6/sec \
		--hashlimit-burst 32 \
	-j LOG \
	-m limit --limit 1/sec --log-ip-options --log-prefix "<|srcds-ipt|> signed_on flood: "

iptables -I PREROUTING 16 $CMD_BASE $CMD_COMMENT $CMD_PORTS \
	-m set --match-set signed_on src,dst \
	-m set ! --match-set permatrusted src \
	-m hashlimit \
		--hashlimit-name signedon_speedlimit \
		--hashlimit-mode srcip,dstport \
		--hashlimit-above 6/sec \
		--hashlimit-burst 32 \
	-j DROP


# Not loged udp spam limit
iptables -I PREROUTING 17 $CMD_BASE $CMD_COMMENT $CMD_PORTS \
	-m hashlimit \
		--hashlimit-name speedlimit \
		--hashlimit-mode srcip,dstport \
		--hashlimit-above 6/sec \
		--hashlimit-burst 10 \
	-m set ! --match-set permatrusted src \
	-m set ! --match-set signed_on src,dst \
	-j LOG \
	-m limit --limit 2/min --log-ip-options --log-prefix "<|srcds-ipt|> udp spam: "

iptables -I PREROUTING 18 $CMD_BASE $CMD_COMMENT $CMD_PORTS \
	-m hashlimit \
		--hashlimit-name speedlimit \
		--hashlimit-mode srcip,dstport \
		--hashlimit-above 6/sec \
		--hashlimit-burst 10 \
	-m set ! --match-set permatrusted src \
	-m set ! --match-set signed_on src,dst \
	-j DROP
