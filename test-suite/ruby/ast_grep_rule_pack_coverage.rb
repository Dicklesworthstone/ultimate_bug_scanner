require "digest"
require "json"
require "net/http"
require "openssl"
require "tempfile"
require "yaml"

MUTABLE_LIST = []

class RulePackCoverageController
  skip_before_action :verify_authenticity_token

  def exercise(params, record, object, method_name, id, payload, blob, path)
    value = params[:value]
    value == nil
    value != nil
    params[:enabled].equal?(true)
    1.0 == 1.0
    params[:ready] and params[:enabled]

    eval(params[:code])
    Marshal.load(blob)
    YAML.load(blob)
    Digest::MD5.hexdigest(params[:password])
    rand(10)

    http = Net::HTTP.new("example.com", 443)
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE

    method_name = params[:method]
    object.send(method_name, params[:argument])
    ActiveRecord::Base.connection.execute("select * from users where id = #{id}")
    system("rm -rf #{path}")
    open("|ls #{path}")
    JSON.parse(payload)
    File.open(path, "w")
    Tempfile.new("ubs")
    worker = Thread.new { puts params[:background] }

    "User".constantize
    record.update_attributes(params)
    params.permit!

    begin
      risky_operation
    rescue
      puts "rescued"
    end

    begin
      risky_operation
    rescue Exception => ex
      warn ex.message
    end

    begin
      risky_operation
    rescue StandardError => err
      raise err
    end

    begin
      risky_operation
    rescue StandardError
      warn "retry failed"
      retry
    end

    worker
  end
end
