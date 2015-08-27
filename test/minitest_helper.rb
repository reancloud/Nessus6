require 'codeclimate-test-reporter'
CodeClimate::TestReporter.start
$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'Nessus6'
require 'hurley/test'
require 'minitest/autorun'

module Nessus6Test
end
