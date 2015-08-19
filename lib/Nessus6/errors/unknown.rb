module Nessus6
  module Error
    # UnknownError represents something that Nessus doesn't
    # provide an HTTP code for
    class UnknownError < StandardError
    end
  end
end
