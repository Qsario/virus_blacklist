Virus Blacklist
===============

This is a simple Ruby interface for [CYMRU's DNS virus blacklist](http://www.team-cymru.org/Services/MHR/).

Usage
-----

This gem takes in the MD5 hash of a file and looks it up using CYMRU's DNS-based
blacklist.  Its usage is incredibly simple:

```ruby
require 'virus_blacklist' 
require 'digest'  

file = '/path/to/file'	# Pick some file to scan  
hash = Digest::MD5.hexdigest(File.read(file)) # Create an MD5 hash for it  

VirusBlacklist.resolver.query_timeout = 5   # Configure our Dnsruby::Resolver 
VirusBlacklist.scan(hash)   # Returns :safe :unsafe :unknown or :error  
VirusBlacklist.is_ok?(hash) # False if scan returns :unsafe, True otherwise  
```

Dependencies
------------

This uses the Dnsruby gem to do DNS resolution.  You can access the
Dnsruby::Resolver object at VirusBlacklist.resolver in order to set any of its
options as demonstrated above where we set the query timeout to 5 seconds.  See
the [Dnsruby documentation](http://dnsruby.rubyforge.org/) for further information.

Most non-virus files will come up as :unknown and DNS timeouts may cause scan to
return :error so this does not provide much security.  Changing even one bit of a
malicious file will change the MD5 hash.  At most, this might help curtail the
spread of files known to be malicious, but it provides absolutely no assurance
that a file is safe.  Whether or not that is better than nothing depends on
whether or not it lulls you into a false sense of security.

