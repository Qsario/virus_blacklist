require 'dnsruby'

module VirusBlacklist

  # CYMRU publishes the MD5 hashes of known viruses as DNS A records.  In short:
  # You get 127.0.0.1 back if the file is in their registry and marked as safe.
  # You get 127.0.0.2 back if the file is in their registry and marked as unsafe.
  # You get NXDOMAIN if the file isn't in their registry at all.
  # You may also get no reply if you're being rate limited.
  #
  # If you ask for TXT records, you can get information on the detection rate,
  # but we don't use this.  The service is free for non-commercial use.
  # See http://www.team-cymru.org/Services/MHR/ for more info.

  include Dnsruby
  extend self 

  def resolver
    # This is our Dnsruby::Resolver object.  You can modify its settings via this.  For example,
    # VirusBlacklist.resolver.query_timeout = 5
    #
    # Our default query_timeout is very aggresive:  2 seconds.  You might want to wait longer, 
    # depending on the application.

    @resolver ||= Dnsruby::Resolver.new(:query_timeout => 2)  # Only waits for 2 seconds
  end

  def scan(md5)

    # Checks for a file in their blacklist.
    #
    # Example:
    #	>> VirusBlacklist.scan(virus_hash)
    #	=> :unsafe
    #
    # Arguments:
    #	md5: (String)	- String containing an MD5 hash.  Must be exactly 32 hexadecimal digits.
    #
    # Possible Outputs:
    #	:safe	  - Hash in registry, not detected as virus.
    #	:unsafe	  - Hash in registry, known virus
    #	:unknown  - Hash not in registry.  Most files will be unknown.
    #	:error	  - We got an unexpected IP back in reply.  Could occur due to SiteFinder and
    #		    other ISP tools that mask NXDOMAIN responses.

    unless md5.match(/\A[a-f0-9]{32}\z/i)
      # MD5s are exactly 32 hex characters.
      raise ArgumentError, "Invalid MD5 value (" + md5 + "). MD5s contain exactly 32 hexadecimal digits." 
    end

    begin
      case resolver.query(md5.downcase + ".malware.hash.cymru.com", Types.A).answer[0].address.to_s
	when /\A127\.0\.0\.1\z/
	  return :safe
	when /\A127\.0\.0\.2\z/
	  return :unsafe
	else
	  # This usually happens due to something like SiteFinder returning its own IP.
	  return :error
      end

    rescue NXDomain, ResolvTimeout
      # Hashes not in the DB (i.e. almost everything) will end up as NXDomain unless you have SiteFinder
      # or some other ISP "feature" feeding you phony results that lead to some page full of ads.
      # You might also get timeouts due to DNS problems, or if rate limited.
      return :unknown
    end
    
  end

  def is_ok?(md5)

    # A simple interpreter for scan that considers everything but :unsafe to be ok.
    #
    # Example:
    #	>> VirusBlacklist.is_ok?(virus_hash)
    #	=> false
    #
    # Arguments:
    #	md5: (String)	- String containing an MD5 hash.  Must be exactly 32 hexadecimal digits.
    #
    # Output:
    #	false	- if scan says :unsafe
    #	true	- if scan says anything else (including :error)
    #
    # Unfortunately, we're limited by the fact that this is a blacklist and that there's
    # no way to whitelist every possible benign file.  So we consider it safe if it's
    # not known to be bad.  That doesn't matter much, because it's  also trivial to change 
    # any unimportant part of a malicious file, which will change its hash.
    #
    # The :error result is hard to interpret.  Tools like SiteFinder create false errors by
    # masking NXDOMAIN results which would make everything look like a virus.  On the other
    # hand, your DNS cache might be poisoned.  If that happens, though, you have bigger
    # problems.

    if scan(md5) == :unsafe
      return false
    else
      return true
    end
  end

end
