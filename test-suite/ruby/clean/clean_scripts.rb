# frozen_string_literal: true

require 'yaml'
require 'open3'

class SafeService
  def safe_eval(token)
    raise ArgumentError, 'bad token' unless %w[ALLOW DENY].include?(token)

    token == 'ALLOW'
  end

  def deserialize(payload)
    YAML.safe_load(payload, symbolize_names: true)
  end

  def run(command, *args)
    status = Open3.capture2e(command, *args)
    status
  end

  def join_threads(threads)
    threads.each(&:join)
  end
end
