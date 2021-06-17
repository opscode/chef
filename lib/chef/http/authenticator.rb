#--
# Author:: Daniel DeLeo (<dan@chef.io>)
# Copyright:: Copyright (c) Chef Software Inc.
# License:: Apache License, Version 2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require "chef/mixin/powershell_exec"
require_relative "auth_credentials"
require_relative "../exceptions"
autoload :OpenSSL, "openssl"

class Chef
  class HTTP
    class Authenticator

      DEFAULT_SERVER_API_VERSION = "2".freeze

      include Chef::Mixin::PowershellExec

      attr_reader :signing_key_filename
      attr_reader :raw_key
      attr_reader :attr_names
      attr_reader :auth_credentials
      attr_reader :version_class
      attr_reader :api_version

      attr_accessor :sign_request

      def initialize(opts = {})
        @raw_key = nil
        @sign_request = true
        @signing_key_filename = opts[:signing_key_filename]
        @key = load_signing_key(opts[:signing_key_filename], opts[:raw_key])
        @auth_credentials = AuthCredentials.new(opts[:client_name], @key, use_ssh_agent: opts[:ssh_agent_signing])
        @version_class = opts[:version_class]
        @api_version = opts[:api_version]
      end

      def handle_request(method, url, headers = {}, data = false)
        headers["X-Ops-Server-API-Version"] = request_version
        headers.merge!(authentication_headers(method, url, data, headers)) if sign_requests?
        [method, url, headers, data]
      end

      def handle_response(http_response, rest_request, return_value)
        [http_response, rest_request, return_value]
      end

      def stream_response_handler(response)
        nil
      end

      def handle_stream_complete(http_response, rest_request, return_value)
        [http_response, rest_request, return_value]
      end

      def request_version
        if version_class
          version_class.best_request_version
        elsif api_version
          api_version
        elsif Chef::ServerAPIVersions.instance.negotiated?
          Chef::ServerAPIVersions.instance.max_server_version.to_s
        else
          DEFAULT_SERVER_API_VERSION
        end
      end

      def sign_requests?
        auth_credentials.sign_requests? && @sign_request
      end

      def client_name
        @auth_credentials.client_name
      end

      # def load_signing_key(key_file, raw_key = nil)
      #   if !!key_file
      #     @raw_key = IO.read(key_file).strip
      #   elsif !!raw_key
      #     @raw_key = raw_key.strip
      #   else
      #     return nil
      #   end
      #   # Pass in '' as the passphrase to avoid OpenSSL prompting on the TTY if
      #   # given an encrypted key. This also helps if using a single file for
      #   # both the public and private key with ssh-agent mode.
      #   @key = OpenSSL::PKey::RSA.new(@raw_key, "")
      # rescue SystemCallError, IOError => e
      #   Chef::Log.warn "Failed to read the private key #{key_file}: #{e.inspect}"
      #   raise Chef::Exceptions::PrivateKeyMissing, "I cannot read #{key_file}, which you told me to use to sign requests!"
      # rescue OpenSSL::PKey::RSAError
      #   msg = "The file #{key_file} or :raw_key option does not contain a correctly formatted private key or the key is encrypted.\n"
      #   msg << "The key file should begin with '-----BEGIN RSA PRIVATE KEY-----' and end with '-----END RSA PRIVATE KEY-----'"
      #   raise Chef::Exceptions::InvalidPrivateKey, msg
      # end

      def load_signing_key(key_file, raw_key = nil)
        results = retrieve_certificate_key(Chef::Config[:node_name])
        puts "\n"
        puts " auth.rb - This is the key file name I am trying to load : #{key_file}"
        puts " auth.rb - Is there a raw_key name? : #{raw_key ? raw_key : false}"
        puts " auth.rb - Chef Config thinks this is my node name : #{Chef::Config[:node_name]}"
        puts " auth.rb - Is the Global @node_name available here? : #{@node_Name ? @node_name : false}"
        puts "\n"
        if key_file == nil? && raw_key == nil?
          puts "\nNo key detected\n"
        elsif results != false
          # results variable holds 2 values - "False" or the contents of a key.
          @raw_key = results
          puts "\n"
          puts "Hey. I think I got a key back! #{results}"
        # first time chef-client runs, generate node-name and burn that to the client.rb
        # use that node name to create a p12/pfx on the fly
        # store that
        # add in code to dump key from certstore
        # what key am I looking for? Should it be named Chef-Client or the S/N of the node or what? - it is the node name as derived from what is listed in the client.rb
        # - Open the client.rb, ::File.read(client.rb)
        # - Hit that with a regex to get the node name out
        #
        #
        #   contents = ::File.read(::File.join(ChefConfig::Config.etc_chef_dir, "client.rb"))
        #   node_name = contents.match(/^node_name.*$/).to_s.split(" ")[1].split(/\W+/)
        #
        # - Extract the pfx that matches that from Progress Key hive in HKLM I created earlier, node_name : some_random_value
        # - extract the key, delete anything on disk
        # - connect to Chef Server
        # key_file and raw_key nil, check the certstore if Windows, keychain if Mac?
        #
        # Chef::Logger("Could not find the key in cert store, falling back to client.pem on disk")
        # Check for the presence of a validation.pem file and delete it after my new client key is registered with the chef server.
        #
        elsif !!key_file
          @raw_key = IO.read(key_file).strip
        elsif !!raw_key
          @raw_key = raw_key.strip
        else
          return nil
        end
        # Pass in '' as the passphrase to avoid OpenSSL prompting on the TTY if
        # given an encrypted key. This also helps if using a single file for
        # both the public and private key with ssh-agent mode.
        @key = OpenSSL::PKey::RSA.new(@raw_key, "")
      rescue SystemCallError, IOError => e
        Chef::Log.warn "Failed to read the private key #{key_file}: #{e.inspect}"
        raise Chef::Exceptions::PrivateKeyMissing, "I cannot read #{key_file}, which you told me to use to sign requests!"
      rescue OpenSSL::PKey::RSAError
        msg = "The file #{key_file} or :raw_key option does not contain a correctly formatted private key or the key is encrypted.\n"
        msg << "The key file should begin with '-----BEGIN RSA PRIVATE KEY-----' and end with '-----END RSA PRIVATE KEY-----'"
        raise Chef::Exceptions::InvalidPrivateKey, msg
      end

      def retrieve_certificate_key(client_name)
        if ChefUtils.windows?
          check_and_retrieve_certstore_for_key(client_name)
        elsif ChefUtils.macos?
          check_keychain_for_key(client_name)
        else # generic return for Linux systemss
          false
        end
      end

      def check_and_retrieve_certstore_for_key(client_name)
        # This code block assumes a certificate with a subject name like "Chef-<node-name>" is in the \LocalMachine\My store and
        # that here is a password stored in the registry to be used to export the pfx with.

        require "openssl" unless defined?(OpenSSL)

        powershell_password_code = <<~CODE
            Try {
                Get-ItemPropertyValue -Path "HKLM:\\Software\\Progress\\Authenticator" -Name "PfxPass" -ErrorAction Stop;
            }
            Catch {
                return $false
            }
        CODE
        password = powershell_exec!(powershell_password_code).result

        powershell_code = <<~CODE
            Try {
                $pfspass = "#{password}"
                $my_pwd = ConvertTo-SecureString -String $pfspass -Force -AsPlainText;
                $cert = Get-ChildItem -path cert:\\LocalMachine\\My -Recurse | Where-Object { $_.Subject -match "#{client_name}" } -ErrorAction Stop;
                $tempfile = [System.IO.Path]::GetTempPath() + "exportpfx.pfx";
                Export-PfxCertificate -Cert $cert -Password $my_pwd -FilePath $tempfile;
            }
            Catch {
                return $false
            }
        CODE
        myresult = powershell_exec!(powershell_code).result

        pkcs = OpenSSL::PKCS12.new(File.binread(myresult["PSPath"].split("::")[1]), password)
        ::File.delete(myresult["PSPath"].split("::")[1])
        return OpenSSL::PKey::RSA.new(pkcs.key.to_pem)
      end

      def authentication_headers(method, url, json_body = nil, headers = nil)
        request_params = {
          http_method: method,
          path: url.path,
          body: json_body,
          host: "#{url.host}:#{url.port}",
          headers: headers,
        }
        request_params[:body] ||= ""
        auth_credentials.signature_headers(request_params)
      end
    end
  end
end
