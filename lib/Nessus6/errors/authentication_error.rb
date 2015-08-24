module Nessus6
  # The Error module is used to house error conditions for the Nessus6 tool
  module Error
    # Authentication error is thrown when the user cannot authenticate with
    # Nessus
    class AuthenticationError < StandardError
    end
  end
end
