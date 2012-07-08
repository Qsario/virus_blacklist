require 'test/unit'
require 'virus_blacklist'

class VirusBlacklistTest < Test::Unit::TestCase

  def setup
    # Example MD5 for a virus
    @virus_hash = "733a48a9cb49651d72fe824ca91e8d00"

    # MD5 for an empty file
    @safe_hash = "d41d8cd98f00b204e9800998ecf8427e"
  end

  def test_dns
    # Make sure Dnsruby can do its thing.
    assert_equal Dnsruby::Resolver,
      VirusBlacklist.resolver.class
  end

  def test_example_malicious_file_not_ok
    # The example of a malicious file's MD5 hash comes from CYMRU's
    # documentation.
    assert !VirusBlacklist.is_ok?(@virus_hash)
  end

  def test_example_malicious_file_scan_unsafe
    # Make sure their example virus shows up as unsafe.
    assert_equal :unsafe,
      VirusBlacklist.scan(@virus_hash)
  end

  def test_example_safe_file
    # This is the MD5 of an empty file.  Scan says it's :unknown
    # right now, but they could mark it as safe someday, so we
    # only test is_ok? instead of doing a scan.
    assert VirusBlacklist.is_ok?(@safe_hash)
  end

  def test_file_probe
    # We can't test the exact data because it might change, but
    # we can at least make sure that we're getting some data
    # for this.  Though it could raise ResolvTimeout if the
    # DNS server is too slow.
    assert_equal false,
      VirusBlacklist.probe(@virus_hash).nil?
  end

  def test_hash_checker_true
    # Make sure a valid MD5 hash is seen as valid.
    assert VirusBlacklist.valid_hash?(@virus_hash)
  end

  def test_hash_checker_false
    # Test and make sure a string that's not a hash won't work.
    assert_equal false,
      VirusBlacklist.valid_hash?("invalid")
  end

end

