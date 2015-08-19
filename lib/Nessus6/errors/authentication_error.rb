module Nessus6
  module Error
    # Authentication error is thrown when the user cannot authenticate with
    # Nessus
    class AuthenticationError < StandardError
    end
  end
end
