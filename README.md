smudge
======

Smudge is a Windows forensics tool with a simple premise, attackers are lazy when
installing persistence mechanisms. Persistence usually involves installing some 
mechanism on a compromised machine to allow the attacker continued access to the 
machine across reboots, updates, and password changes. However, while these 
persistence mechanisms may actually be well hidden and the C2 agents patient, many 
professional pieces of penetration testing software are so careless as to leave 
unobfuscated strings on disk or unsantized strings in memory. Smudge takes 
advantage of this by searching disk and process memory for strings resembling http 
resources, domain names and IP addresses. Smudge's purpose is to point out anomalies
 and shed light on suspicious files and processes. Smudge leaves judgement of what
is malware up to the operator.
