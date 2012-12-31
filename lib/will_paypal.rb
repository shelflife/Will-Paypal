require "logger"
require "net/https"
require "cgi"

class WillPaypal

  attr_accessor :config, :logger

  DEFAULT_OPTIONS = {
    :cert_path => '/etc/ssl/certs',
    :sandbox   => false,
    :aa_api    => false,
    :params    => {}
  }

  def initialize(config={})
    self.config = DEFAULT_OPTIONS.merge(config)
    self.logger = config.delete(:logger) || Logger.new(STDOUT)
    self.config[:url] ||= self.config[:sandbox] ? "https://api-3t.sandbox.paypal.com/nvp" : "https://api-3t.paypal.com/nvp"
  end

  def query_string_for(data)
    if self.config[:aa_api]
      data.merge!({
        "X-PAYPAL-APPLICATION-ID"     => self.config[:application_id],
        "X-PAYPAL-SECURITY-USERID"    => self.config[:userid],
        "X-PAYPAL-SECURITY-PASSWORD"  => self.config[:password],
        "X-PAYPAL-SECURITY-SIGNATURE" => self.config[:signature],
      })
    else
      data.merge!({
        "USER"       => self.config[:user],
        "PWD"        => self.config[:password],
        "SIGNATURE"  => self.config[:signature],
        "VERSION"    => self.config[:version],
      })
    end

    data.merge!(self.config[:params])
    query = []
    data.each do |key, value|
      formatted_key = self.config[:aa_api] ? key.to_s : key.to_s.upcase
      query << "#{formatted_key}=#{CGI.escape(value.to_s)}"
    end
    query.sort.join("&")
  end

  def hash_from_query_string(query_string)
    hash = {}
    query_string.split("&").each do |element|
      a = element.split("=")
      hash[a[0]] = CGI.unescape(a[1]) if a.size == 2
    end
    hash
  end

  def call_paypal(data)
    uri = URI.parse(self.config[:url])

    http                = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl        = true
    http.read_timeout   = self.config[:timeout] if self.config[:timeout]

    http.verify_mode    = OpenSSL::SSL::VERIFY_PEER
    http.verify_depth   = 5

    if self.config[:cert_file] && File.exists?(self.config[:cert_file])
      http.ca_file = self.config[:cert_file]
    elsif File.directory?(self.config[:cert_path])
      http.ca_path = self.config[:cert_path]
    else
      self.logger.warn "WARNING: no ssl certs found. Paypal communication will be insecure. DO NOT DEPLOY"
      http.verify_mode  = OpenSSL::SSL::VERIFY_NONE
      http.verify_depth = nil
    end

    response = http.request_post(uri.path, self.query_string_for(data))
    response_hash = { :status => response.code, :body => response.body, :parsed_body => {} }

    if response.kind_of? Net::HTTPSuccess
      response_hash[:parsed_body].merge! self.hash_from_query_string(response.body)
    end
    response_hash
  end

end
