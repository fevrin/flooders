#!/bin/bash

file=/tmp/1

strip_file() {
   sed -i.bak -re 's;^time=.+msg="(.+)"$;\1;' $file
}

check_dest_ip() {
# returns a list of desination IPs, their counts, and their organization
   echo "checking destination IP..."

   ip_regex="([0-9]{1,3}\.){3}[0-9]{1,3}"
   local output=$(check_file_for "$(grep -Eoi --color=always "destination: $ip_regex" $file | sed 's;destination: ;;i')")

   echo "$output" | while read; do
      local count=$(echo $REPLY | grep -Eo '^[0-9]+')
      local ip=$(echo $REPLY | grep -Eo "$ip_regex")
      local orgname="$(get-orgname-from-ip $ip)"
      orgname=${orgname:="not found"}

      echo -e "$REPLY ($orgname)"
   done
}

get-orgname-from-ip() {
# returns the OrgName for the given IP address
# input: a valid IP address
# output: OrgName for the given IP
   ip=$1
   whois $ip | sed -rne 's;^(OrgName|org-name|descr):\s+(.+)$;\2;p' | sort -u | head -n1
}

check_file_for() {
   local specifics="$1"
   [[ -n $specifics ]] && echo "$specifics" | sort | uniq -c | sort -n | tail -n5 | sed -r 's;^ +;;'
}

check_dest_port() {
   echo "checking destination port..."
   check_file_for "$(grep -Eoi --color=always 'destination port: [0-9]+' $file | sed 's;destination port: ;;i')"
}

check_syn() {
   echo "checking syns committed..."
   total_syns=$(grep -Eoi --color=always '(0x002)' $file | sort | uniq -c | sed -r 's;^ +;;')
   if [[ -n "$total_syns" ]]; then
      echo "$total_syns"
   else
      echo "0 syns"
   fi
}

check_udp() {
   echo "checking udp..."
   check_file_for "$(grep -Eoi --color=always 'user datagram protocol[^"\n]*' $file)"
}

total_packets() {
   grep -E --color=always "Frame [0-9]+:" $file | tail
}

check_dns_amp() {
   echo "checking DNS amplification..."
   check_file_for "$(grep -Eoi --color=always 'Recursion desired: Do query recursively' $file)"
}

strip_file

check_dest_ip
echo

check_dest_port
echo

check_syn
echo

check_udp
echo

check_dns_amp
