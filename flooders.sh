#!/bin/bash

file=/tmp/2

strip_file() {
   sed -i.bak -re 's;^time=.+msg="(.+)"$;\1;' $file
}

check_dest_ip() {
   grep -Eoi --color=always 'destination: ([0-9]{1,3}\.){3}[0-9]{1,3}' $file | sed 's;destination: ;;i' | sort | uniq -c | sort -n | tail -n5 | sed -r 's;^ +;;'
}

check_dest_port() {
   grep -Eoi --color=always 'destination port: [0-9]+' $file | sed 's;destination port: ;;i' | sort | uniq -c | sort -n | tail -n5 | sed -r 's;^ +;;'
}

check_syn() {
   total_syns=$(grep -Eoi --color=always '(0x002)' $file | sort | uniq -c | sed -r 's;^ +;;')
   if [[ -n "$total_syns" ]]; then
      echo "$total_syns"
   else
      echo "0 syns"
   fi
}

check_udp() {
   grep -Eoi --color=always 'user datagram protocol[^"\n]*' $file | sort | uniq -c | sort -n | sed -r 's;^ +;;'
}

total_packets() {
   grep -E --color=always "Frame [0-9]+:" $file | tail
}

check_dns_amp() {
   grep -Eoi --color=always 'Recursion desired: Do query recursively' $file | sort | uniq -c | sort -n | sed -r 's;^ +;;'
}

strip_file

echo "checking destination IP..."
check_dest_ip
echo

echo "checking destination port..."
check_dest_port
echo

echo "checking syn..."
check_syn
echo

echo "checking udp..."
check_udp
echo

echo "checking DNS amplification"
check_dns_amp
