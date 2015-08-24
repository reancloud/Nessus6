require 'json'
require 'nessus6/errors/bad_request'
require 'nessus6/errors/conflict'
require 'nessus6/errors/forbidden'
require 'nessus6/errors/internal_server_error'
require 'nessus6/errors/not_found'
require 'nessus6/errors/unauthorized'
require 'nessus6/errors/unknown'

module Nessus6
  # The verification class allows methods to verify responses from Nessus
  module Verification
    private

    def verify(response, message = nil)
      case response.status_code
      when 200
        return JSON.parse response.body
      when 400
        fail Nessus6::Error::BadRequestError, "#{message[:bad_request]}"
      when 401
        fail Nessus6::Error::UnauthorizedError, "#{message[:unauthorized]}"
      when 403
        fail Nessus6::Error::ForbiddenError, "#{message[:forbidden]}"
      when 404
        fail Nessus6::Error::NotFoundError, "#{message[:not_found]}"
      when 409
        fail Nessus6::Error::ConflictError, "#{message[:conflict]}"
      when 500
        fail Nessus6::Error::InternalServerError,
             "#{message[:internal_server_error]}"
      else
        fail Nessus6::Error::UnknownError, 'An unknown error occurred. ' \
                           'Please consult Nessus for further details.'
      end
    end
  end
end