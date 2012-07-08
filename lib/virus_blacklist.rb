require 'dnsruby'

# CYMRU publishes the MD5 hashes of known viruses as DNS records, which is perfect for us.  In short:
# You get 127.0.0.1 back if the file is in their registry and marked as safe.
# You get 127.0.0.2 back if the file is in their registry and marked as unsafe.
# You get NXDOMAIN if the file isn't in their registry at all.
# You may also get no reply if you're being rate limited.
# See http://www.team-cymru.org/Services/MHR/ for more info on this service.

module VirusBlacklist

  include Dnsruby
  extend self 

  def resolver
    # Our default query_timeout is pretty aggressive.  You might want to wait longer, depending
    # on the application.
    @resolver ||= Dnsruby::Resolver.new(:query_timeout => 2)  # Only waits for 2 seconds
  end

  # For testing, use md5 = "733a48a9cb49651d72fe824ca91e8d00" which should get marked as a known virus.
  # That example is directly from their documentation on the service.

  def scan(md5)
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
	  return :unknown
      end
    
    rescue Exception => e
      puts e.message
      return :error
    end
  end

  def is_ok?(md5)
    # Unfortunately, we're limited by the fact that this is a blacklist and that there's
    # no way to whitelist every possible benign file.  So we consider it safe if it's
    # not known to be bad.  That doesn't matter much, because it's  also trivial to change 
    # any unimportant part of a malicious file, which will change its hash.  So this is poor
    # security, but it's the best we can do.

    if scan(md5) == :unsafe
      return false
    else
      return true
    end
  end

end
