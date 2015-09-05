# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'Nessus6/version'

Gem::Specification.new do |spec|
  spec.name          = 'Nessus6'
  spec.version       = Nessus6::VERSION
  spec.authors       = ['Kevin Kirsche']
  spec.email         = ['kev.kirsche@gmail.com']
  spec.license       = 'Apache-2.0'

  spec.summary       = '[Under Construction] Nessus 6 API Gem'
  spec.description   = 'Gem for interacting with the Tenable Nessus 6 REST API.'
  spec.homepage      = 'https://github.com/kkirsche/Nessus6'

  spec.required_ruby_version = '>= 2.0.0'

  spec.files         = `git ls-files -z`.split("\x0").reject do |files|
    files.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_development_dependency 'bundler', '~> 1.5'
  spec.add_development_dependency 'rake', '~> 10.0'
  spec.add_development_dependency 'minitest', '~> 5.8'
  spec.add_development_dependency 'yard', '~> 0.8'
  spec.add_development_dependency 'codeclimate-test-reporter', '~> 0.4'
  spec.add_runtime_dependency 'hurley', '~> 0.2'
end
