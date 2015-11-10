

#!/usr/bin/env ruby

require "ipaddress"

onionSerialFlag = "onion-serial-number"
onionSerialSep  = "="
ignore = "192.168.%"
netmask = "32"

t = Time.now

sigs =	[
	"ET WEB_SERVER%",
	"ET CURRENT_EVENTS DNS Amplification%",
	"ET SCAN ZmEu%",
	"ET CURRENT_EVENTS Malformed HeartBeat%",
	"ET CURRENT_EVENTS TLS HeartBeat%",
	"ET CURRENT_EVENTS Possible OpenSSL HeartBleed%",
	"ET CURRENT_EVENTS Possible TLS HeartBleed%",
	"ET DROP Dshield Block%",
	"ET CURRENT_EVENTS Possible ZyXELs ZynOS%",
	"ET SCAN Tomcat%",
	"ET SCAN Paros%",
	"ET COMPROMISED Known Compromised%",
	"ET WEB_SPECIFIC_APPS WBBlog SQL Injection%",
	"ET CURRENT_EVENTS Joomla Component%",
	"ET WEB_SPECIFIC_APPS iWare Professional%",
	"ET WEB_SPECIFIC_APPS Possible WP CuckooTap",
	"ET SCAN Core-Project%",
	"ET MALWARE Fake Mozilla User-Agent%",
	"ET MALWARE Mozilla User-Agent%Inbound Likely Fake",
	"GPL DNS named version attempt",
	"ET WEB_SERVER Muieblackcat",
	"ET SCAN NETWORK Incoming%",
	"ET TROJAN Palevo%",
	"ET DOS Possible NTP DDoS%"
	]

ips = [] # will fill this with mysql results later

out = ""

out += "### NGFW - Next Ghettoration Fire Wall - IPs to block from Onion Alerts ###\n"
out += "### Onion report generated at #{t} \n"
out += "# #{onionSerialFlag}#{onionSerialSep}#{t.strftime("%s")} \n"
out += "# Number of rules in effect: #{sigs.size} \n"
sigs.each do |sig| out += "# #{sig} \n" end

sigs.each do |sig|
  qry = "select distinct inet_ntoa(src_ip) as ip , signature from securityonion_db.event where inet_ntoa(src_ip) not like \\\"#{ignore}\\\" and signature like \\\"#{sig}\\\" order by timestamp asc "
  
  res = `mysql -u root -e \" #{qry} \"`

  res.split("\n").each do |row|
    next if not IPAddress::valid_ipv4? row.split("\t")[0]
    out += "#{row.split("\t")[0]}/#{netmask} # #{row.split("\t")[1]} \n"
  end

end

#your mom
puts out
