# Copyright:: Copyright (c) Chef Software Inc.
#
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

require "train"
require "tempfile" unless defined?(Tempfile)
require "uri" unless defined?(URI)
require "securerandom" unless defined?(SecureRandom)

class Chef
  class Knife
    class Bootstrap < Knife
      class TrainConnector
        SSH_CONFIG_OVERRIDE_KEYS ||= %i{user port proxy}.freeze

        MKTEMP_WIN_COMMAND ||= <<~EOM.freeze
          $parent = [System.IO.Path]::GetTempPath();
          [string] $name = [System.Guid]::NewGuid();
          $tmp = New-Item -ItemType Directory -Path (Join-Path $parent $name);
          $tmp.FullName
        EOM

        DEFAULT_REMOTE_TEMP ||= "/tmp".freeze

        def initialize(host_url, default_protocol, opts)
          @host_url = host_url
          @default_protocol = default_protocol
          @opts_in = opts
        end

        def config
          @config ||= begin
                        uri_opts = opts_from_uri(@host_url, @default_protocol)
                        transport_config(@host_url, @opts_in.merge(uri_opts))
                      end
        end

        def connection
          @connection ||= begin
                       Train.validate_backend(config)
                       train = Train.create(config[:backend], config)
                       # Note that the train connection is not currently connected
                       # to the remote host, but it's ready to go.
                       train.connection
                     end
        end

        #
        # Establish a connection to the configured host.
        #
        # @raise [TrainError]
        # @raise [TrainUserError]
        #
        # @return [TrueClass] true if the connection could be established.
        def connect!
          # Force connection to establish
          connection.wait_until_ready
          true
        end

        #
        # @return [String] the configured hostname
        def hostname
          config[:host]
        end

        # Answers the question, "is this connection configured for password auth?"
        # @return [Boolean] true if the connection is configured with password auth
        def password_auth?
          config.key? :password
        end

        # Answers the question, "Am I connected to a linux host?"
        #
        # @return [Boolean] true if the connected host is linux.
        def linux?
          connection.platform.linux?
        end

        # Answers the question, "Am I connected to a unix host?"
        #
        # @note this will always return true for a linux host
        # because train classifies linux as a unix
        #
        # @return [Boolean] true if the connected host is unix or linux
        def unix?
          connection.platform.unix?
        end

        #
        # Answers the question, "Am I connected to a Windows host?"
        #
        # @return [Boolean] true if the connected host is Windows
        def windows?
          connection.platform.windows?
        end

        #
        # Creates a temporary directory on the remote host if it
        # hasn't already. Caches directory location. For *nix,
        # it will ensure that the directory is owned by the logged-in user
        #
        # @return [String] the temporary path created on the remote host.
        def temp_dir
          @tmpdir ||= if windows?
                        run_command!(MKTEMP_WIN_COMMAND).stdout.split.last
                      else
                        # Get a 6 chars string using secure random
                        # eg. /tmp/chef_XXXXXX.
                        # Use mkdir to create TEMP dir to get rid of mktemp
                        dir = "#{DEFAULT_REMOTE_TEMP}/chef_#{SecureRandom.alphanumeric(6)}"
                        run_command!("mkdir -p '#{dir}'")
                        # Ensure that dir has the correct owner.  We are possibly
                        # running with sudo right now - so this directory would be owned by root.
                        # File upload is performed over SCP as the current logged-in user,
                        # so we'll set ownership to ensure that works.
                        run_command!("chown #{config[:user]} '#{dir}'") if config[:sudo]

                        dir
                      end
        end

        #
        # Uploads a file from "local_path" to "remote_path"
        #
        # @param local_path [String] The path to a file on the local file system
        # @param remote_path [String] The destination path on the remote file system.
        # @return NilClass
        def upload_file!(local_path, remote_path)
          connection.upload(local_path, remote_path)
          nil
        end

        #
        # Uploads the provided content into the file "remote_path" on the remote host.
        #
        # @param content [String] The content to upload into remote_path
        # @param remote_path [String] The destination path on the remote file system.
        # @return NilClass
        def upload_file_content!(content, remote_path)
          t = Tempfile.new("chef-content")
          t.binmode
          t << content
          t.close
          upload_file!(t.path, remote_path)
          nil
        ensure
          t.close
          t.unlink
        end

        #
        # Force-deletes the file at "path" from the remote host.
        #
        # @param path [String] The path of the file on the remote host
        def del_file!(path)
          if windows?
            run_command!("If (Test-Path \"#{path}\") { Remove-Item -Force -Path \"#{path}\" }")
          else
            run_command!("rm -f \"#{path}\"")
          end
          nil
        end

        #
        # normalizes path across OS's - always use forward slashes, which
        # Windows and *nix understand.
        #
        # @param path [String] The path to normalize
        #
        # @return [String] the normalized path
        def normalize_path(path)
          path.tr("\\", "/")
        end

        #
        # Runs a command on the remote host.
        #
        # @param command [String] The command to run.
        # @param data_handler [Proc] An optional block. When provided, inbound data will be
        # published via `data_handler.call(data)`. This can allow
        # callers to receive and render updates from remote command execution.
        #
        # @return [Train::Extras::CommandResult] an object containing stdout, stderr, and exit_status
        def run_command(command, &data_handler)
          connection.run_command(command, &data_handler)
        end

        #
        # Runs a command the remote host
        #
        # @param command [String] The command to run.
        # @param data_handler [Proc] An optional block. When provided, inbound data will be
        # published via `data_handler.call(data)`. This can allow
        # callers to receive and render updates from remote command execution.
        #
        # @raise Chef::Knife::Bootstrap::RemoteExecutionFailed if an error occurs (non-zero exit status)
        # @return [Train::Extras::CommandResult] an object containing stdout, stderr, and exit_status
        def run_command!(command, &data_handler)
          result = run_command(command, &data_handler)
          if result.exit_status != 0
            raise RemoteExecutionFailed.new(hostname, command, result)
          end

          result
        end

        private

        # For a given url and set of options, create a config
        # hash suitable for passing into train.
        def transport_config(host_url, opts_in)
          # These baseline opts are not protocol-specific
          opts = { target: host_url,
                   www_form_encoded_password: true,
                   transport_retries: 2,
                   transport_retry_sleep: 1,
                   backend: opts_in[:backend],
                   logger: opts_in[:logger] }

          # Accepts options provided by caller if they're not already configured,
          # but note that they will be constrained to valid options for the backend protocol
          opts.merge!(opts_from_caller(opts, opts_in))

          # WinRM has some additional computed options
          opts.merge!(opts_inferred_from_winrm(opts, opts_in))

          # Now that everything is populated, fill in anything missing
          # that may be found in user ssh config
          opts.merge!(missing_opts_from_ssh_config(opts))

          Train.target_config(opts)
        end

        # Some winrm options are inferred based on other options.
        # Return a hash of winrm options based on configuration already built.
        def opts_inferred_from_winrm(config, opts_in)
          return {} unless config[:backend] == "winrm"

          opts_out = {}

          if opts_in[:ssl]
            opts_out[:ssl] = true
            opts_out[:self_signed] = opts_in[:self_signed] || false
          end

          # See note here: https://github.com/mwrock/WinRM#example
          if %w{ssl plaintext}.include?(opts_in[:winrm_auth_method])
            opts_out[:winrm_disable_sspi] = true
          end
          opts_out
        end

        # Returns a hash containing valid options for the current
        # transport protocol that are not already present in config
        def opts_from_caller(config, opts_in)
          # Train.options gives us the supported config options for the
          # backend provider (ssh, winrm). We'll use that
          # to filter out options that don't belong
          # to the transport type we're using.
          valid_opts = Train.options(config[:backend])
          opts_in.select do |key, _v|
            valid_opts.key?(key) && !config.key?(key)
          end
        end

        # Extract any of username/password/host/port/transport
        # that are in the URI and return them as a config has
        def opts_from_uri(uri, default_protocol)
          # Train.unpack_target_from_uri only works for complete URIs in
          # form of proto://[user[:pass]@]host[:port]/
          # So we'll add the protocol prefix if it's not supplied.
          uri_to_check = if URI::DEFAULT_PARSER.make_regexp.match(uri)
                           uri
                         else
                           "#{default_protocol}://#{uri}"
                         end

          Train.unpack_target_from_uri(uri_to_check)
        end

        # This returns a hash that consists of settings
        # populated from SSH configuration that are not already present
        # in the configuration passed in.
        # This is necessary because train will default these values
        # itself - causing SSH config data to be ignored
        def missing_opts_from_ssh_config(config)
          return {} unless config[:backend] == "ssh"

          host_cfg = ssh_config_for_host(config[:host])
          opts_out = {}
          host_cfg.each do |key, _value|
            if SSH_CONFIG_OVERRIDE_KEYS.include?(key) && !config.key?(key)
              opts_out[key] = host_cfg[key]
            end
          end
          opts_out
        end

        # Having this as a method makes it easier to mock
        # SSH Config for testing.
        def ssh_config_for_host(host)
          require "net/ssh" unless defined?(Net::SSH)
          Net::SSH::Config.for(host)
        end
      end

      class RemoteExecutionFailed < StandardError
        attr_reader :exit_status, :command, :hostname, :stdout, :stderr

        def initialize(hostname, command, result)
          @hostname = hostname
          @exit_status = result.exit_status
          @stderr = result.stderr
          @stdout = result.stdout
        end
      end

    end
  end
end
