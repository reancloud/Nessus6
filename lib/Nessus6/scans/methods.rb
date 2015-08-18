require 'json'
require 'Nessus6/errors/forbidden' # 403
require 'Nessus6/errors/not_found' # 404
require 'Nessus6/errors/unknown'

module Nessus6
  # The Editor class is for interacting with Nessus6 templates
  class Scans
    def initialize(client)
      @client = client
    end

    def launch(scan_id, alt_targets = nil)
      response = @client.post("scans/#{scan_id}/launch") unless alt_targets.is_a? Array
      verify_launch response
    end

    private

    def verify_launch(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 403
        fail ForbiddenError, 'This scan is disabled.'
      when 404
        fail NotFoundError, 'Scan does not exist.'
      when 500
        fail NotFoundError, 'Failed to launch scan. This is usually due to the'\
          ' scan already running.'
      else
        fail UnknownError, 'An unknown error occurred. Please consult Nessus' \
                           'for further details.'
      end
    end
  end
end
