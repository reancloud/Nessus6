require 'minitest_helper'

module Nessus6Test
  describe 'Client', 'The Nessus 6 API Client' do
    it 'should have a version number' do
      expect(Nessus6::VERSION).wont_be_nil
    end
  end
end
