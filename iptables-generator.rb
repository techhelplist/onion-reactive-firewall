

#!/usr/bin/env ruby

require "open-uri"
require "openssl"

# user set-able varaibles
onionSauce = " [ url to onion-generated blocklist ] "
onionSerialFlag = "onion-serial-number"
onionSerialSep  = "="

# these get values below
curRules = ""
ips = []
onionSerialThisReport = ""


puts " "
puts " == welcome to onion rule importer == "
puts " -- asks onion for a list to block, creates iptables rules to block -- "
puts " "

if not ARGV.empty? and ARGV[0] == "purge"
  puts "purge mode."
  curRules = `iptables -L -n --line-numbers | grep #{onionSerialFlag}`.split("\n")
  puts "#{curRules.size} rules in effect. removing..."
  curRules.each do |rule|
    newTopRule = `iptables -L -n --line-numbers | grep #{onionSerialFlag}`.split("\n")[0]
    line = newTopRule.split(" ")[0]
    `iptables -D INPUT 1`
  end
  exit 0
end

module OpenSSL
  module SSL
    remove_const :VERIFY_PEER
  end
end
OpenSSL::SSL::VERIFY_PEER = OpenSSL::SSL::VERIFY_NONE


begin
  puts " collecting existing rules  "
  curRules = `iptables -L -n --line-numbers | grep #{onionSerialFlag}`.split("\n")
  puts "  currently have #{curRules.size} onion rules in effect"

  puts " downloading new onion data  "
   data = URI.parse(onionSauce).read
   data.each_line do |line|
    if line.match(onionSerialFlag+onionSerialSep)
      onionSerialThisReport = line.strip.split(onionSerialSep)[1]
    end
    next if line[0] == "#"
    ipAndNetmask = line.split("#")[0].strip
    ip = ipAndNetmask.split("/")[0].strip
    netmask = ipAndNetmask.split("/")[1].strip
    ips.push(ip)
  end
  ips.uniq!  

  puts "  data serial=#{onionSerialThisReport} includes #{ips.size} rules"

  areChanges = `iptables -L -n --line-numbers | grep #{onionSerialFlag} | grep -v #{onionSerialThisReport} | wc -l`.to_i
  if curRules.size > 0 and areChanges == 0
    puts "  rules exist but there are no changes. exiting."
  else  

  # add the new rules
  puts " adding the new rules"
  ips.uniq.each do |ip|
    `iptables -I INPUT -s #{ip} -j DROP -m comment --comment "#{onionSerialFlag}#{onionSerialSep}#{onionSerialThisReport}"`
  end

  oldRules = curRules #easier to think about
  curRules = `iptables -L -n --line-numbers | grep #{onionSerialFlag}`.split("\n")
  puts "  now we have #{curRules.size} onion rules in effect"

  # delete the old rules

  # old way didnt work if old report stayed same
  puts " old ruleset included #{oldRules.size} rules. removing..."
  oldRules.each do |rule|
    lowestOldRule = `iptables -L -n --line-numbers | grep #{onionSerialFlag} | grep -v #{onionSerialThisReport}`.split("\n")[0]
    lowestOldRuleLineNumber = lowestOldRule.split(" ")[0]
    puts "  lowest old rule num, i would delete him : " + lowestOldRuleLineNumber
    #puts "  " + rule
    #line = rule.split(" ")[0]
    `iptables -D INPUT #{lowestOldRuleLineNumber}`
  end

  curRules = `iptables -L -n --line-numbers | grep #{onionSerialFlag}`.split("\n")
  puts "  now left with #{curRules.size} onion rules in effect"
  curRules.each do |rule|
    #puts "   " + rule
  end
  end # the else

rescue Exception => e
  #if the whole thing goes bad, just remove the onion rules
  puts "the whole thing just went bad. removing all onion rules..."
  puts e.message
  curRules = `iptables -L -n --line-numbers | grep #{onionSerialFlag}`.split("\n")
  curRules.each do |rule|
    line = rule.split(" ")[0]
    puts line
    `iptables -D INPUT #{line}`
  end
  exit 1

