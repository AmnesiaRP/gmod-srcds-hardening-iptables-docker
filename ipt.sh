# ipset:
# * signed_on
# * permatrusted


# TSEQ: |54536f7572636520456e67696e65205175657279|

# Test count: -s <ME> ! match-set validated -j ACCEPT


# Log and DROP invalid packets
iptables -I PREROUTING 1 -t mangle -p all \
	-m comment --comment=srcds-hardening \
	-m state --state INVALID \
	-j LOG \
	-m limit --limit 2/min --log-ip-options --log-prefix <|srcds-ipt|> INVALID PKT: 
	
iptables -I PREROUTING 2 -t mangle -p all \
	-m comment --comment=srcds-hardening \
	-m state --state INVALID \
	-j DROP

# data: TSEQ | hashlimit: srcip,dstport | limit: 6/min | j: DROP
iptables -I PREROUTING 1 -t raw -p udp -i vmbr0 \
	-m comment --comment=srcds_hardening \
	-m multiport --dports 27000:29000 \
	-m string --algo bm --hex-string |54536f7572636520456e67696e65205175657279| \
	-m hashlimit \
		--hashlimit-name tseq \
		--hashlimit-mode srcip,dstport \
		--hashlimit-above 6/min \
		--hashlimit-burst 8 \
	-j DROP

# data: TSEQ | limit: 100/sec | j: ACCEPT | else: DROP
iptables -I PREROUTING 2 -t raw -p udp -i vmbr0 \
	-m comment --comment=srcds_hardening \
	-m multiport --dports 27000:29000 \
	-m string --algo bm --hex-string |54536f7572636520456e67696e65205175657279| \
	-m limit --limit 100/sec
	-j ACCEPT

iptables -I PREROUTING 3 -t raw -p udp -i vmbr0 \
	-m comment --comment=srcds_hardening \
	-m multiport --dports 27000:29000 \
	-m string --algo bm --hex-string |54536f7572636520456e67696e65205175657279| \
	-j DROP
	

# Log flair signon and add to signed_on set
iptables -I PREROUTING 4 -t raw -p udp -i vmbr0 \
	-m comment --comment=srcds-hardening \
	-m multiport --dports 27000:29000 \
	-m string --algo bm --hex-string |3030303030303030303000| \
	-m length --length 48 --from 26 --to 48 \
	-j LOG \
	-m limit --limit 250/min --log-ip-options --log-level error --log-prefix <|srcds-ipt|> signon: 

iptables -I PREROUTING 5 -t raw -p udp -i vmbr0 \
	-m comment --comment=srcds-hardening \
	-m multiport --dports 27000:29000 \
	-m string --algo bm --hex-string |3030303030303030303000| \
	-m length --length 48 --from 26 --to 48 \
	-j SET --add-set signed_on src,dst --timeout 60


# Update timeout in signed_on (should be removed)
iptables -I PREROUTING 6 -t raw -p udp -i vmbr0 \
	-m comment --comment=srcds-hardening \
	-m set --match-set signed_on src,dst \
	-j SET --add-set signed_on src,dst --timeout 600 --exist


# Log and DROP small packets
iptables -I PREROUTING 7 -t raw -p udp -i vmbr0 \
	-m comment --comment=srcds-hardening \
	-m multiport --dports 27000:29000 \
	-m length --length 0:32 \
	-j LOG \
	-m limit --limit 2/min --log-ip-options --log-prefix <|srcds-ipt|> len < 32: 

iptables -I PREROUTING 8 -t raw -p udp -i vmbr0 \
	-m comment --comment=srcds-hardening \
	-m multiport --dports 27000:29000 \
	-m length --length 0:32 \
	-j DROP


# Log and DROP bigass packets
iptables -I PREROUTING 9 -t raw -p udp -i vmbr0 \
	-m comment --comment=srcds-hardening \
	-m multiport --dports 27000:29000 \
	-m length --length 2521:65535 \
	-j LOG \
	-m limit --limit 2/min --log-ip-options --log-prefix <|srcds-ipt|> len > 2521: 

iptables -I PREROUTING 10 -t raw -p udp -i vmbr0 \
	-m comment --comment=srcds-hardening \
	-m multiport --dports 27000:29000 \
	-m length --length 2521:65535 \
	-j DROP


# Rate limit permatrusted (ACCEPT should be removed)
iptables -I PREROUTING 11 -t raw -p udp -i vmbr0 \
	-m comment --comment=srcds-hardening \
	-m set --match-set permatrusted src \
	-m hashlimit \
		--hashlimit-name validated_speedlimit \
		--hashlimit-mode srcip,dstport \
		--hashlimit-above 72/sec \
		--hashlimit-burst 80 \
	-j DROP

iptables -I PREROUTING 12 -t raw -p udp -i vmbr0 \
	-m comment --comment=srcds-hardening \
	-m set --match-set permatrusted src \
	-j ACCEPT


# Rate limit flair loged (should be replaced with a very strict burst)
iptables -I PREROUTING 13 -t raw -p udp -i vmbr0 \
	-m comment --comment=srcds-hardening \
	-m set --match-set signed_on src,dst \
	-m hashlimit \
		--hashlimit-name signedon_speedlimit \
		--hashlimit-mode srcip,dstport \
		--hashlimit-above 18/sec \
		--hashlimit-burst 20 \
	-j DROP

iptables -I PREROUTING 14 -t raw -p udp -i vmbr0 \
	-m comment --comment=srcds-hardening \
	-m set --match-set signed_on src,dst \
	-j ACCEPT


# Not loged udp spam limit
iptables -I PREROUTING 15 -t raw -p udp -i vmbr0 \
	-m comment --comment=srcds-hardening \
	-m multiport --dports 27000:29000 \
	-m hashlimit \
		--hashlimit-name speedlimit \
		--hashlimit-mode srcip,dstport \
		--hashlimit-above 7/sec \
		--hashlimit-burst 10 \
	-m set ! --match-set permatrusted src \
	-m set ! --match-set signed_on src,dst \
	-j LOG \
	-m limit --limit 2/min --log-ip-options --log-prefix <|srcds-ipt|> udp spam:
 
iptables -I PREROUTING 16 -t raw -p udp -i vmbr0 \
	-m comment --comment=srcds-hardening \
	-m multiport --dports 27000:29000 \
	-m hashlimit \
		--hashlimit-name speedlimit \
		--hashlimit-mode srcip,dstport \
		--hashlimit-above 7/sec \
		--hashlimit-burst 10 \
	-m set ! --match-set permatrusted src \
	-m set ! --match-set signed_on src,dst \
	-j DROP


