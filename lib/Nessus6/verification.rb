require 'json'
require 'Nessus6/error/bad_request'
require 'Nessus6/error/conflict'
require 'Nessus6/error/forbidden'
require 'Nessus6/error/internal_server_error'
require 'Nessus6/error/method_not_allowed'
require 'Nessus6/error/not_found'
require 'Nessus6/error/unauthorized'
require 'Nessus6/error/unknown'

# The Nessus6 module is used to interact with Nessus version 6 servers.
module Nessus6
  # The verification class allows methods to verify responses from Nessus
  module Verification
    private

    def verify(response, message = nil)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 400
        fail Nessus6::Error::BadRequestError, "#{message[:bad_request]} | Response: #{response.body}"
      when 401
        fail Nessus6::Error::UnauthorizedError, "#{message[:unauthorized]} | Response: #{response.body}"
      when 403
        fail Nessus6::Error::ForbiddenError, "#{message[:forbidden]} | Response: #{response.body}"
      when 404
        fail Nessus6::Error::NotFoundError, "#{message[:not_found]} | Response: #{response.body}"
      when 405
        fail Nessus6::Error::MethodNotAllowedError, "#{message[:not_allowed]} | Response: #{response.body}"
      when 409
        fail Nessus6::Error::ConflictError, "#{message[:conflict]} | Response: #{response.body}"
      when 500
        fail Nessus6::Error::InternalServerError,
             "#{message[:internal_server_error]} | Response: #{response.body}"
      else
        fail Nessus6::Error::UnknownError, 'An unknown error occurred. ' \
                           'Please consult Nessus for further details.'
      end
    end
  end
end
