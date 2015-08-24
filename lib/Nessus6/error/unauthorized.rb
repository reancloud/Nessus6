module Nessus6
  module Error
    # UnauthorizedError represents HTTP 401 Responses
    # Similar to 403 Forbidden, but specifically for use
    # when authentication is required and has failed or has
    # not yet been provided. The response must include a
    # WWW-Authenticate header field containing a challenge
    # applicable to the requested resource
    class UnauthorizedError < StandardError
    end
  end
end
