$LOAD_PATH.unshift File.expand_path('../lib', __FILE__)
require 'mnemonic'

Gem::Specification.new do |s|
  s.name = 'mnemonic'
  s.summary = 'Mnemonic words and seed generator based on BIP-39'
  s.description = 'This implementation conforms to BIP-39 and PBKDF2 RFC 2898, and has been tested using the test vectors in https://github.com/trezor/python-mnemonic and Appendix B of RFC 3962.'
  s.email = 'mail@sreekanth.in'
  s.homepage = 'http://github.com/sreekanthgs/mnemonic'
  s.authors = ['Sreekanth GS']
  s.version = Mnemonic::VERSION
  s.add_development_dependency 'rspec'
  s.add_development_dependency 'rdoc'
  s.files = Dir['lib/**/*.rb']
end
