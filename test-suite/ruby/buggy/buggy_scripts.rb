# frozen_string_literal: false

require 'yaml'

API_SECRET = 'shhhh'

class Buggy
  def insecure_eval(input)
    eval(input) # CRITICAL: eval
  end

  def deserialize(payload)
    YAML.load(payload) # CRITICAL: unsafe load
  end

  def run(command)
    system("sh -c \"#{command}\"") # command injection
  end

  def leaky_thread
    Thread.new do
      sleep 10
    end
  end
end

Thread.new { puts 'never joined' }
