module Nessus6
  module Error
    # NotFoundError represents HTTP 404 Responses
    # The requested resource could not be found but may be
    # available again in the future. Subsequent requests by
    # the client are permissible.
    class NotFoundError < StandardError
    end
  end
end
