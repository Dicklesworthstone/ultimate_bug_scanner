# frozen_string_literal: true

require 'open-uri'

module SecurityHygiene
  def self.open_user_url(url)
    uri = URI.parse(url)
    allowed = %w[https].include?(uri.scheme)
    raise ArgumentError, 'invalid scheme' unless allowed

    uri.open
  end

  def self.safe_eval(token)
    raise 'not allowed' unless token == 'ALLOW'
  end
end
