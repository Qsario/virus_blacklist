Virus Blacklist
===============

This is a simple Ruby interface for CYMRU's DNS virus blacklist.  You can read
more about it at: http://www.team-cymru.org/Services/MHR/

This gem takes in the MD5 hash of a file and looks it up using CYMRU's DNS-based
blacklist Usage is incredibly simple:

require 'virus_blacklist' 
require 'digest'

file = '/path/to/file' 
hash = Digest::MD5.hexdigest(File.read(file))

# Wait this many seconds before returning :error
VirusBlacklist.resolver.query_timeout = 5  

VirusBlacklist.scan(hash)   # Returns :safe :unsafe :unknown or :error
VirusBlacklist.is_ok?(hash) # False if scan returns :unsafe, True otherwise

This uses the Dnsruby gem to do resolution.  You can access the
Dnsruby::Resolver object at VirusBlacklist.resolver in order to set any of its
options as demonstrated above where we set the query_timeout.  See
http://dnsruby.rubyforge.org/ for further information.

Most non-virus files will come up as :unknown and DNS timeouts may cause scan to
return :error  This does not provide much security.  Changing even one bit of a
malicious file will change the hash.  At most, this might help curtail the
spread of files known to be malicious, but it provides absolutely no assurance
that a file is safe.  Whether or not this is better than nothing depends on
whether it lulls you into a false sense of security.
