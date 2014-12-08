#!/bin/bash

file=/tmp/1
hits=15

strip_file() {
   sed -i.bak -re 's;^time=.+msg="(.+)?"$;\1;' -e 's;\\n;\n;g' $file
}

check_ip() {
# returns a list of desination IPs, their counts, and their organization
   local input="$1"
   local direction=""

   if [[ "$input" =~ (src|source) ]]; then
      direction="source"
   elif [[ "$input" =~ (dst|destination)? ]]; then
      direction="destination"
   fi

   echo "checking top $hits $direction IPs..."

   ip_regex="([0-9]{1,3}\.){3}[0-9]{1,3}"
   local output=$(check_file_for "$(grep -Eoi --color=always "$direction: $ip_regex" $file | sed "s;$direction: ;;i")")

   echo "$output" | while read; do
      local count=$(echo $REPLY | grep -Eo '^[0-9]+')
      local ip=$(echo $REPLY | grep -Eo "$ip_regex")
      local orgname="$(get-orgname-from-ip $ip)"
      orgname=${orgname:="not found"}

      echo -e "$REPLY ($orgname)"
   done
}

check_src_ip() {
# returns a list of source IPs, their counts, and their organization
   check_ip src
}

check_dest_ip() {
# returns a list of desination IPs, their counts, and their organization
   check_ip dst
}

get-orgname-from-ip() {
# returns the OrgName for the given IP address
# input: a valid IP address
# output: OrgName for the given IP
   ip=$1
   # kill whois if it takes too long on an IP
   timeout -s15 2 whois $ip 2>/dev/null | sed -rne 's;^(OrgName|org-name|descr):\s+(.+)$;\2;p' | sort -u | head -n1
}

check_file_for() {
   local specifics="$1"
   [[ -n $specifics ]] && echo "$specifics" | sort | uniq -c | sort -n | tail -n$hits | sed -r 's;^ +;;'
}

check_dest_port() {
   echo "checking top $hits destination ports..."
   check_file_for "$(grep -Eoi --color=always 'destination port: [0-9]+' $file | sed 's;destination port: ;;i')"
}

check_syn() {
   echo "checking syns committed..."
   total_syns=$(check_file_for "$(grep -Eoi --color=always '(0x002)' $file)")
   if [[ -n "$total_syns" ]]; then
      echo "$total_syns"
   else
      echo "0 syns"
   fi
}

check_bogus_header() {
   echo "checking for bogus headers..."

   total_bogus_header=$(check_file_for "$(grep -Eoi --color=always 'Header length: .*\(bogus, must be at least 20\)' $file)")
   if [[ -n "$total_bogus_header" ]]; then
      echo "$total_bogus_header"
   else
      echo "0 bogus headers"
   fi
}

check_udp() {
   echo "checking udp..."

   total_udp_packets=$(check_file_for "$(grep -Eoi --color=always 'user datagram protocol[^"\n]*' $file)")
   if [[ -n "$total_udp_packets" ]]; then
      echo "$total_udp_packets"
   else
      echo "0 udp packets"
   fi
}

check_blank_packets(){
   echo "checking blank packets..."
   grep -Eoi --color=always '  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' $file
}

total_packets() {
   grep -E --color=always "Frame [0-9]+:" $file | tail
}

check_dns_amp() {
   echo "checking DNS amplification..."

   total_dns_amp=$(check_file_for "$(grep -Eoi --color=always 'Recursion desired: Do query recursively' $file)")
   if [[ -n "$total_dns_amp" ]]; then
      echo "$total_dns_amp"
   else
      echo "0 dns amp"
   fi
}

strip_file

check_src_ip
echo

check_dest_ip
echo

check_dest_port
echo

check_syn
echo

check_udp
echo

check_dns_amp
echo

check_bogus_header
