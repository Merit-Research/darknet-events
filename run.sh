#!/bin/sh

c=$1

case $c in
"asn-only")
	./local/parse --threshold 624 --samples 3 \
		--eventout "../out/results_2021-03-11.01.2.json" \
		--pcap "../data/2021-03-11.01.pcap.gz" \
		--asnin "../data/GeoLite2-ASN.mmdb"
	echo "asn only"
;;
"geo-only")
	./local/parse --threshold 624 --samples 3 \
		--eventout "../out/results_2021-03-11.01.2.json" \
		--pcap "../data/2021-03-11.01.pcap.gz" \
		--geoin "../data/GeoLite2-City.mmdb"
	echo "geo only"
;;
"pfx2as-only")
	./local/parse --threshold 624 --samples 3 \
		--eventout "../out/results_2021-03-11.01.2.json" \
		--pcap "../data/2021-03-11.01.pcap.gz" \
		--pfx2asin "../data/routeviews-rv2-20201201-1200.pfx2as.gz"
	echo "pfx2as only"
;;
"all")
	./local/parse --threshold 624 --samples 3 \
		--eventout "../out/results_2021-03-11.01.2.json" \
		--pcap "../data/2021-03-11.01.pcap.gz" \
		--asnin "../data/GeoLite2-ASN.mmdb" \
		--geoin "../data/GeoLite2-City.mmdb" \
		--pfx2asin "../data/routeviews-rv2-20201201-1200.pfx2as.gz"
	echo "all flags present"
;;
"basic")
	./local/parse --threshold 624 --samples 3 \
		--eventout "../out/results_2021-03-11.01.2.json" \
		--pcap "../data/2021-03-11.01.pcap.gz"
	echo "basic usage"
;;
esac

cat "../out/results_2021-03-11.01.2.json" | python3 -m json.tool > "../out/pretty_2021-03-11.01.2.json"

