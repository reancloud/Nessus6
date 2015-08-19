module Nessus6
  module Error
    # InternalServerError represents HTTP 500 Responses
    # A generic error message, given when an unexpected condition
    # was encountered and no more specific message is suitable
    class InternalServerError < StandardError
    end
  end
end
