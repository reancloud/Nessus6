module Nessus6
  module Error
    # ForbiddenError represents HTTP 403 Responses
    # The request was a valid request, but the server
    # is refusing to respond to it. Unlike 401 Unauthorized
    # responses, authenticating will make no difference
    class ForbiddenError < StandardError
    end
  end
end
