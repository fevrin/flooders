#!/bin/bash

# define the file containing the plaintext (not pcap) tcpdump
file=/tmp/1

# define how many results to show for source and destination IPs and ports
hits=15

if [[ $(which timeout) ]]; then
   timeout_command="timeout -s15 2"
fi

strip_file() {
   local contents=$(sed -rne 's;^(time=.+msg="|@cee:\{"msg":")([^"]+)".*$;\2;p' $file | egrep -v '(^@cee:{"msg"|\\n)')
   if [[ -n "$contents" ]]; then
      echo "$contents" > $file
   else
      echo "couldn't strip file further"
   fi
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
   local output=$(check_file_for "$(egrep -oi --color=always "$direction: $ip_regex" $file | sed "s;$direction: ;;i")")

   echo "$output" | while read; do
      local count=$(echo $REPLY | egrep -o '^[0-9]+')
      local ip=$(echo $REPLY | egrep -o "$ip_regex")
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
   $timeout_command whois $ip 2>/dev/null | sed -rne 's;^(OrgName|org-name|descr|owner):\s+(.+)$;\2;p' | sort -u | head -n1
}

check_file_for() {
   local specifics="$1"
   [[ -n $specifics ]] && echo "$specifics" | sort | uniq -c | sort -n | tail -n$hits | sed -r 's;^ +;;'
}

check_src_port() {
   echo "checking top $hits source ports..."
   check_file_for "$(egrep -oi --color=always 'source port: [0-9]+' $file | sed 's;source port: ;;i')"
}

check_dest_port() {
   echo "checking top $hits destination ports..."
   check_file_for "$(egrep -oi --color=always 'destination port: [0-9]+' $file | sed 's;destination port: ;;i')"
}

check_syn() {
   echo "checking syns committed..."
   total_syns=$(check_file_for "$(egrep -oi --color=always '1. = Syn: Set' $file)")
   if [[ -n "$total_syns" ]]; then
      echo "$total_syns"
   else
      echo "0 syns"
   fi
}

check_bogus_header() {
   echo "checking for bogus headers..."

   total_bogus_header=$(check_file_for "$(egrep -oi --color=always 'Header length: .*\(bogus, must be at least 20\)' $file)")
   if [[ -n "$total_bogus_header" ]]; then
      echo "$total_bogus_header"
   else
      echo "0 bogus headers"
   fi
}

check_udp() {
   echo "checking udp..."

   total_udp_packets=$(check_file_for "$(egrep -oi --color=always 'user datagram protocol[^"\n]*' $file)")
   if [[ -n "$total_udp_packets" ]]; then
      echo "$total_udp_packets"
   else
      echo "0 udp packets"
   fi
}

check_blank_packets(){
   echo "checking blank packets..."
   egrep -oi --color=always '  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' $file
}

total_packets() {
   egrep --color=always "Frame [0-9]+:" $file | tail
}

check_dns_amp() {
   echo "checking DNS amplification..."

   total_dns_amp=$(check_file_for "$(egrep -oi --color=always 'Recursion desired: Do query recursively' $file)")
   if [[ -n "$total_dns_amp" ]]; then
      echo "$total_dns_amp"
   else
      echo "0 dns amp"
   fi
}

check_total_packets_captured() {
   local count=$(egrep -o '^Frame [0-9]+:' $file | sort -u | wc -l)
   echo "total packets captured: $count"
}

strip_file

check_src_ip
echo

check_dest_ip
echo

check_src_port
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
echo
check_total_packets_captured
