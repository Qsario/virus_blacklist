Gem::Specification.new do |s|
  s.name = 'virus_blacklist'
  s.version = '1.1.0'
  s.date = '2012-07-08'
  s.summary = 'Interface for CYMRU DNS-based virus blacklist.'
  s.description = 'A simple interface for the CYMRU DNS-based virus blacklist.'
  s.authors = ["Matt Venzke"]
  s.email = 'mvenzke@gmail.com'
  s.files = ["lib/virus_blacklist.rb"]
  s.homepage = 'https://github.com/Qsario/virus_blacklist'
  s.add_runtime_dependency 'dnsruby', '~> 1.5'
end
