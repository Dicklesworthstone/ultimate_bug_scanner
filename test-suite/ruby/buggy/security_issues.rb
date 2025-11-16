# frozen_string_literal: false

require 'open-uri'

module BuggySecurity
  def self.open_user_url(url)
    # BUG: open-uri with arbitrary URL + disable ssl verify
    URI.parse(url).open(ssl_verify_mode: OpenSSL::SSL::VERIFY_NONE)
  end

  def self.dynamic_eval(code)
    binding.eval(code)
  end
end
