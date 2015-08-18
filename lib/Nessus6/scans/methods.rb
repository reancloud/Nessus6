require 'json'
require 'Nessus6/errors/forbidden' # 403
require 'Nessus6/errors/not_found' # 404
require 'Nessus6/errors/conflict' # 409
require 'Nessus6/errors/internal_server_error' # 500
require 'Nessus6/errors/unknown'

module Nessus6
  # The Editor class is for interacting with Nessus6 templates
  class Scans
    def initialize(client)
      @client = client
    end

    def launch(scan_id, alt_targets = nil)
      if alt_targets.is_a? Array
        response = @client.post "scans/#{scan_id}/launch",
                                alt_targets: alt_targets
      else
        response = @client.post "scans/#{scan_id}/launch"
      end

      verify_launch response
    end

    def list
      response = @client.get 'scans'
      JSON.parse response.body
    end

    def pause(scan_id)
      response = @client.post "scans/#{scan_id}/pause"
      verify_pause response
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
        fail InternalServerError, 'Failed to launch scan. This is usually due to the'\
          ' scan already running.'
      else
        fail UnknownError, 'An unknown error occurred. Please consult Nessus' \
                           'for further details.'
      end
    end

    def verify_pause(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 403
        fail ForbiddenError, 'This scan is disabled.'
      when 409
        fail ConflictError, 'Scan is not active.'
      else
        fail UnknownError, 'An unknown error occurred. Please consult Nessus' \
                           'for further details.'
      end
    end
  end
end
