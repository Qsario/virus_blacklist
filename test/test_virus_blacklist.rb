require 'test/unit'
require 'virus_blacklist'

class VirusBlacklistTest < Test::Unit::TestCase

  def test_dns
    assert_equal Dnsruby::Resolver,
      VirusBlacklist.resolver.class
  end

  def test_example_malicious_file_not_ok
    # The example of a malicious file's MD5 hash comes from CYMRU's
    # documentation.
    assert_equal false,
      VirusBlacklist.is_ok?("733a48a9cb49651d72fe824ca91e8d00")
  end

  def test_example_malicious_file_scan_unsafe
    assert_equal :unsafe,
      VirusBlacklist.scan("733a48a9cb49651d72fe824ca91e8d00")
  end

  def test_example_safe_file
    # This is the MD5 of an empty file.  Scan says it's :unknown
    # right now, but they could mark it as safe someday, so we
    # only test is_ok? instead of scan.
    assert_equal true,
      VirusBlacklist.is_ok?("d41d8cd98f00b204e9800998ecf8427e")
  end

end
