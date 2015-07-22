require 'json'
require 'Nessus6/errors/forbidden' # 403
require 'Nessus6/errors/not_found' # 404
require 'Nessus6/errors/unknown'

module Nessus6
  # The Editor class is for interacting with Nessus6 templates
  class Permissions
    def initialize(client)
      @client = client
    end

    def change(object_type, object_id, permissions)
      response = @client.put("permissions/#{object_type}/#{object_id}",
                             body: permissions)
      verify_change response
    end

    def list(object_type, object_id)
      response = @client.get("permissions/#{object_type}/#{object_id}")
      verify_list response
    end

    private

    def verify_change(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 403
        fail ForbiddenError, 'You do not have permission to edit the object'
      when 404
        fail NotFoundError, 'Object does not exist'
      else
        fail UnknownError, 'An unknown error occurred. Please consult Nessus' \
                           'for further details.'
      end
    end

    def verify_list(response)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 403
        fail ForbiddenError, 'You do not have permission to view the object'
      when 404
        fail NotFoundError, 'Object does not exist'
      else
        fail UnknownError, 'An unknown error occurred. Please consult Nessus' \
                           'for further details.'
      end
    end
  end
end
