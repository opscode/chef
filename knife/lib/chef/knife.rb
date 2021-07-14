#
# Author:: Adam Jacob (<adam@chef.io>)
# Author:: Christopher Brown (<cb@chef.io>)
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

require "forwardable" unless defined?(Forwardable)
require_relative "knife/version"
require "mixlib/cli" unless defined?(Mixlib::CLI)
require "chef-utils/dsl/default_paths" unless defined?(ChefUtils::DSL::DefaultPaths)
require "chef-utils/dist" unless defined?(ChefUtils::Dist)
require "chef/workstation_config_loader" unless defined?(Chef::WorkstationConfigLoader)
require "chef/mixin/convert_to_class_name" unless defined?(Chef::ConvertToClassName)
require "chef/mixin/default_paths" unless defined?(Chef::Mixin::DefaultPaths)
require_relative "knife/core/subcommand_loader"
require_relative "knife/core/ui"
require "chef/local_mode" unless defined?(Chef::LocalMode)
require "chef/server_api" unless defined?(Chef::ServerAPI)
require "http/authenticator" unless defined?(Chef::HTTP::Authenticator)
require "http/http_request" unless defined?(Chef::HTTP::HTTPRequest)
require "http" unless defined?(Chef::HTTP)
# End

require "pp" unless defined?(PP)

require_relative "application/knife"

class Chef
  class Knife

    Chef::HTTP::HTTPRequest.user_agent = "#{ChefUtils::Dist::Infra::PRODUCT} Knife#{Chef::HTTP::HTTPRequest::UA_COMMON}"

    include Mixlib::CLI
    include ChefUtils::DSL::DefaultPaths
    extend Chef::Mixin::ConvertToClassName
    extend Forwardable

    # @note Backwards Compat:
    #   Ideally, we should not vomit all of these methods into this base class;
    #   instead, they should be accessed by hitting the ui object directly.
    def_delegator :@ui, :stdout
    def_delegator :@ui, :stderr
    def_delegator :@ui, :stdin
    def_delegator :@ui, :msg
    def_delegator :@ui, :ask_question
    def_delegator :@ui, :pretty_print
    def_delegator :@ui, :output
    def_delegator :@ui, :format_list_for_display
    def_delegator :@ui, :format_for_display
    def_delegator :@ui, :format_cookbook_list_for_display
    def_delegator :@ui, :edit_data
    def_delegator :@ui, :edit_hash
    def_delegator :@ui, :edit_object
    def_delegator :@ui, :confirm

    attr_accessor :name_args
    attr_accessor :ui

    # knife acl subcommands are grouped in this category using this constant to verify.
    OPSCODE_HOSTED_CHEF_ACCESS_CONTROL = %w{acl group user}.freeze

    # knife opc subcommands are grouped in this category using this constant to verify.
    CHEF_ORGANIZATION_MANAGEMENT = %w{opc}.freeze

    # Configure mixlib-cli to always separate defaults from user-supplied CLI options
    def self.use_separate_defaults?
      true
    end

    def self.ui
      @ui ||= Chef::Knife::UI.new(STDOUT, STDERR, STDIN, {})
    end

    def self.msg(msg = "")
      ui.msg(msg)
    end

    def self.reset_config_loader!
      @@chef_config_dir = nil
      @config_loader = nil
    end

    def self.reset_subcommands!
      @@subcommands = {}
      @subcommands_by_category = nil
    end

    def self.inherited(subclass)
      super
      unless subclass.unnamed?
        subcommands[subclass.snake_case_name] = subclass
        subcommand_files[subclass.snake_case_name] +=
          if subclass.superclass.to_s == "Chef::ChefFS::Knife"
            # ChefFS-based commands have a superclass that defines an
            # inherited method which calls super. This means that the
            # top of the call stack is not the class definition for
            # our subcommand.  Try the second entry in the call stack.
            [path_from_caller(caller[1])]
          else
            [path_from_caller(caller[0])]
          end
      end
    end

    # Explicitly set the category for the current command to +new_category+
    # The category is normally determined from the first word of the command
    # name, but some commands make more sense using two or more words
    # @param new_category [String] value to set the category to (see examples)
    #
    # @example Data bag commands would be in the 'data' category by default. To
    #  put them in the 'data bag' category:
    #  category('data bag')
    def self.category(new_category)
      @category = new_category
    end

    def self.subcommand_category
      @category || snake_case_name.split("_").first unless unnamed?
    end

    def self.snake_case_name
      convert_to_snake_case(name.split("::").last) unless unnamed?
    end

    def self.common_name
      snake_case_name.split("_").join(" ")
    end

    # Does this class have a name? (Classes created via Class.new don't)
    def self.unnamed?
      name.nil? || name.empty?
    end

    def self.subcommand_loader
      @subcommand_loader ||= Chef::Knife::SubcommandLoader.for_config(chef_config_dir)
    end

    def self.load_commands
      @commands_loaded ||= subcommand_loader.load_commands
    end

    def self.guess_category(args)
      subcommand_loader.guess_category(args)
    end

    def self.subcommand_class_from(args)
      if args.size == 1 && args[0].strip.casecmp("rehash") == 0
        # To prevent issues with the rehash file not pointing to the correct plugins,
        # we always use the glob loader when regenerating the rehash file
        @subcommand_loader = Chef::Knife::SubcommandLoader.gem_glob_loader(chef_config_dir)
      end
      subcommand_loader.command_class_from(args) || subcommand_not_found!(args)
    end

    def self.subcommands
      @@subcommands ||= {}
    end

    def self.subcommand_files
      @@subcommand_files ||= Hash.new([])
    end

    def self.subcommands_by_category
      unless @subcommands_by_category
        @subcommands_by_category = Hash.new { |hash, key| hash[key] = [] }
        subcommands.each do |snake_cased, klass|
          @subcommands_by_category[klass.subcommand_category] << snake_cased
        end
      end
      @subcommands_by_category
    end

    # Shared with subclasses
    @@chef_config_dir = nil

    def self.config_loader
      @config_loader ||= WorkstationConfigLoader.new(nil, Chef::Log)
    end

    def self.load_config(explicit_config_file, profile)
      config_loader.explicit_config_file = explicit_config_file
      config_loader.profile = profile
      config_loader.load

      ui.warn("No knife configuration file found. See https://docs.chef.io/config_rb/ for details.") if config_loader.no_config_found?

      config_loader
    rescue Exceptions::ConfigurationError => e
      ui.error(ui.color("CONFIGURATION ERROR:", :red) + e.message)
      exit 1
    end

    def self.chef_config_dir
      @@chef_config_dir ||= config_loader.chef_config_dir
    end

    # Run knife for the given +args+ (ARGV), adding +options+ to the list of
    # CLI options that the subcommand knows how to handle.
    #
    # @param args [Array] The arguments. Usually ARGV
    # @param options [Mixlib::CLI option parser hash] These +options+ are how
    #   subcommands know about global knife CLI options
    #
    def self.run(args, options = {})
      # Fallback debug logging. Normally the logger isn't configured until we
      # read the config, but this means any logging that happens before the
      # config file is read may be lost. If the KNIFE_DEBUG variable is set, we
      # setup the logger for debug logging to stderr immediately to catch info
      # from early in the setup process.
      if ENV["KNIFE_DEBUG"]
        Chef::Log.init($stderr)
        Chef::Log.level(:debug)
      end

      subcommand_class = subcommand_class_from(args)
      subcommand_class.options = options.merge!(subcommand_class.options)
      subcommand_class.load_deps
      instance = subcommand_class.new(args)
      instance.configure_chef
      instance.run_with_pretty_exceptions
    end

    def self.dependency_loaders
      @dependency_loaders ||= []
    end

    def self.deps(&block)
      dependency_loaders << block
    end

    def self.load_deps
      dependency_loaders.each(&:call)
    end

    OFFICIAL_PLUGINS = %w{lpar openstack push rackspace vcenter}.freeze

    class << self
      def list_commands(preferred_category = nil)
        category_desc = preferred_category ? preferred_category + " " : ""
        msg "Available #{category_desc}subcommands: (for details, knife SUB-COMMAND --help)\n\n"
        subcommand_loader.list_commands(preferred_category).sort.each do |category, commands|
          next if /deprecated/i.match?(category)

          msg "** #{category.upcase} COMMANDS **"
          commands.sort.each do |command|
            subcommand_loader.load_command(command)
            msg subcommands[command].banner if subcommands[command]
          end
          msg
        end
      end

      private

      # @api private
      def path_from_caller(caller_line)
        caller_line.split(/:\d+/).first
      end

      # Error out and print usage. probably because the arguments given by the
      # user could not be resolved to a subcommand.
      # @api private
      def subcommand_not_found!(args)
        ui.fatal("Cannot find subcommand for: '#{args.join(" ")}'")

        # Mention rehash when the subcommands cache(plugin_manifest.json) is used
        if subcommand_loader.is_a?(Chef::Knife::SubcommandLoader::HashedCommandLoader)
          ui.info("If this is a recently installed plugin, please run 'knife rehash' to update the subcommands cache.")
        end

        if CHEF_ORGANIZATION_MANAGEMENT.include?(args[0])
          list_commands("CHEF ORGANIZATION MANAGEMENT")
        elsif category_commands = guess_category(args)
          list_commands(category_commands)
        elsif OFFICIAL_PLUGINS.include?(args[0]) # command was an uninstalled official chef knife plugin
          ui.info("Use `#{ChefUtils::Dist::Infra::EXEC} gem install knife-#{args[0]}` to install the plugin into Chef Workstation")
        else
          list_commands
        end

        exit 10
      end

      # @api private
      def reset_config_path!
        @@chef_config_dir = nil
      end

    end

    reset_config_path!

    # Create a new instance of the current class configured for the given
    # arguments and options
    def initialize(argv = [])
      super() # having to call super in initialize is the most annoying anti-pattern :(
      @ui = Chef::Knife::UI.new(STDOUT, STDERR, STDIN, config)

      command_name_words = self.class.snake_case_name.split("_")

      # Mixlib::CLI ignores the embedded name_args
      @name_args = parse_options(argv)
      @name_args.delete(command_name_words.join("-"))
      @name_args.reject! { |name_arg| command_name_words.delete(name_arg) }

      # knife node run_list add requires that we have extra logic to handle
      # the case that command name words could be joined by an underscore :/
      command_name_joined = command_name_words.join("_")
      @name_args.reject! { |name_arg| command_name_joined == name_arg }

      # Similar handling for hyphens.
      command_name_joined = command_name_words.join("-")
      @name_args.reject! { |name_arg| command_name_joined == name_arg }

      if config[:help]
        msg opt_parser
        exit 1
      end

      # Grab a copy before config merge occurs, so that we can later identify
      # where a given config value is sourced from.
      @original_config = config.dup

      # copy Mixlib::CLI over so that it can be configured in config.rb/knife.rb
      # config file
      Chef::Config[:verbosity] = config[:verbosity] if config[:verbosity]
    end

    def parse_options(args)
      super
    rescue OptionParser::InvalidOption => e
      puts "Error: " + e.to_s
      show_usage
      exit(1)
    end

    # This is all set and default mixlib-config values.  We only need the default
    # values here (the set values are explicitly mixed in again later), but there is
    # no mixlib-config API to get a Hash back with only the default values.
    #
    # Assumption:  since config_file_defaults is the lowest precedence it doesn't matter
    # that we include the set values here, but this is a hack and makes the name of the
    # method a lie.  FIXME: make the name not a lie by adding an API to mixlib-config.
    #
    # @api private
    #
    def config_file_defaults
      Chef::Config[:knife].save(true) # this is like "dup" to a (real) Hash, and includes default values (and user set values)
    end

    # This is only the user-set mixlib-config values.  We do not include the defaults
    # here so that the config defaults do not override the cli defaults.
    #
    # @api private
    #
    def config_file_settings
      Chef::Config[:knife].save(false) # this is like "dup" to a (real) Hash, and does not include default values (just user set values)
    end

    # config is merged in this order (inverse of precedence)
    #  config_file_defaults - Chef::Config[:knife] defaults from chef-config (XXX: this also includes the settings, but they get overwritten)
    #  default_config       - mixlib-cli defaults (accessor from mixlib-cli)
    #  config_file_settings - Chef::Config[:knife] user settings from the client.rb file
    #  config               - mixlib-cli settings (accessor from mixlib-cli)
    #
    def merge_configs
      # Update our original_config - if someone has created a knife command
      # instance directly, they are likely ot have set cmd.config values directly
      # as well, at which point our saved original config is no longer up to date.
      @original_config = config.dup
      # other code may have a handle to the config object, so use Hash#replace to deliberately
      # update-in-place.
      config.replace(config_file_defaults.merge(default_config).merge(config_file_settings).merge(config))
    end

    #
    # Determine the source of a given configuration key
    #
    # @argument key [Symbol] a configuration key
    # @return [Symbol,NilClass] return the source of the config key,
    # one of:
    #   - :cli - this was explicitly provided on the CLI
    #   - :config - this came from Chef::Config[:knife] explicitly being set
    #   - :cli_default - came from a declared CLI `option`'s `default` value.
    #   - :config_default - this came from Chef::Config[:knife]'s defaults
    #   - nil - if the key could not be found in any source.
    #           This can happen when it is invalid, or has been
    #           set directly into #config without then calling #merge_config
    def config_source(key)
      return :cli if @original_config.include? key
      return :config if config_file_settings.key? key
      return :cli_default if default_config.include? key
      return :config_default if config_file_defaults.key? key # must come after :config check

      nil
    end

    # Catch-all method that does any massaging needed for various config
    # components, such as expanding file paths and converting verbosity level
    # into log level.
    def apply_computed_config
      Chef::Config[:color] = config[:color]

      case Chef::Config[:verbosity]
      when 0, nil
        Chef::Config[:log_level] = :warn
      when 1
        Chef::Config[:log_level] = :info
      when 2
        Chef::Config[:log_level] = :debug
      else
        Chef::Config[:log_level] = :trace
      end

      Chef::Config[:log_level] = :trace if ENV["KNIFE_DEBUG"]

      Chef::Config[:node_name]         = config[:node_name]       if config[:node_name]
      Chef::Config[:client_key]        = config[:client_key]      if config[:client_key]
      Chef::Config[:chef_server_url]   = config[:chef_server_url] if config[:chef_server_url]
      Chef::Config[:environment]       = config[:environment]     if config[:environment]

      Chef::Config.local_mode = config[:local_mode] if config.key?(:local_mode)

      Chef::Config.listen = config[:listen] if config.key?(:listen)

      if Chef::Config.local_mode && !Chef::Config.key?(:cookbook_path) && !Chef::Config.key?(:chef_repo_path)
        Chef::Config.chef_repo_path = Chef::Config.find_chef_repo_path(Dir.pwd)
      end
      Chef::Config.chef_zero.host = config[:chef_zero_host] if config[:chef_zero_host]
      Chef::Config.chef_zero.port = config[:chef_zero_port] if config[:chef_zero_port]

      # Expand a relative path from the config directory. Config from command
      # line should already be expanded, and absolute paths will be unchanged.
      if Chef::Config[:client_key] && config[:config_file]
        Chef::Config[:client_key] = File.expand_path(Chef::Config[:client_key], File.dirname(config[:config_file]))
      end

      Mixlib::Log::Formatter.show_time = false
      Chef::Log.init(Chef::Config[:log_location])
      Chef::Log.level(Chef::Config[:log_level] || :error)
    end

    def configure_chef
      # knife needs to send logger output to STDERR by default
      Chef::Config[:log_location] = STDERR
      config_loader = self.class.load_config(config[:config_file], config[:profile])
      config[:config_file] = config_loader.config_location

      # For CLI options like `--config-option key=value`. These have to get
      # parsed and applied separately.
      extra_config_options = config.delete(:config_option)

      merge_configs
      apply_computed_config

      # This has to be after apply_computed_config so that Mixlib::Log is configured
      Chef::Log.info("Using configuration from #{config[:config_file]}") if config[:config_file]

      begin
        Chef::Config.apply_extra_config_options(extra_config_options)
      rescue ChefConfig::UnparsableConfigOption => e
        ui.error e.message
        show_usage
        exit(1)
      end

      Chef::Config.export_proxies
    end

    def show_usage
      stdout.puts("USAGE: " + opt_parser.to_s)
    end

    def run_with_pretty_exceptions(raise_exception = false)
      unless respond_to?(:run)
        ui.error "You need to add a #run method to your knife command before you can use it"
      end
      ENV["PATH"] = default_paths if Chef::Config[:enforce_default_paths] || Chef::Config[:enforce_path_sanity]
      maybe_setup_fips
      Chef::LocalMode.with_server_connectivity do
        run
      end
    rescue Exception => e
      raise if raise_exception || ( Chef::Config[:verbosity] && Chef::Config[:verbosity] >= 2 )

      humanize_exception(e)
      exit 100
    end

    def humanize_exception(e)
      case e
      when SystemExit
        raise # make sure exit passes through.
      when Net::HTTPClientException, Net::HTTPFatalError
        humanize_http_exception(e)
      when OpenSSL::SSL::SSLError
        ui.error "Could not establish a secure connection to the server."
        ui.info "Use `knife ssl check` to troubleshoot your SSL configuration."
        ui.info "If your server uses a self-signed certificate, you can use"
        ui.info "`knife ssl fetch` to make knife trust the server's certificates."
        ui.info ""
        ui.info  "Original Exception: #{e.class.name}: #{e.message}"
      when Errno::ECONNREFUSED, Timeout::Error, Errno::ETIMEDOUT, SocketError
        ui.error "Network Error: #{e.message}"
        ui.info "Check your knife configuration and network settings"
      when NameError, NoMethodError
        ui.error "knife encountered an unexpected error"
        ui.info  "This may be a bug in the '#{self.class.common_name}' knife command or plugin"
        ui.info  "Please collect the output of this command with the `-VVV` option before filing a bug report."
        ui.info  "Exception: #{e.class.name}: #{e.message}"
      when Chef::Exceptions::PrivateKeyMissing
        ui.error "Your private key could not be loaded from #{api_key}"
        ui.info  "Check your configuration file and ensure that your private key is readable"
      when Chef::Exceptions::InvalidRedirect
        ui.error "Invalid Redirect: #{e.message}"
        ui.info  "Change your server location in config.rb/knife.rb to the server's FQDN to avoid unwanted redirections."
      else
        ui.error "#{e.class.name}: #{e.message}"
      end
    end

    def humanize_http_exception(e)
      response = e.response
      case response
      when Net::HTTPUnauthorized
        ui.error "Failed to authenticate to #{server_url} as #{username} with key #{api_key}"
        ui.info "Response:  #{format_rest_error(response)}"
      when Net::HTTPForbidden
        ui.error "You authenticated successfully to #{server_url} as #{username} but you are not authorized for this action."
        proxy_env_vars = ENV.to_hash.keys.map(&:downcase) & %w{http_proxy https_proxy ftp_proxy socks_proxy no_proxy}
        unless proxy_env_vars.empty?
          ui.error "There are proxy servers configured, your server url may need to be added to NO_PROXY."
        end
        ui.info "Response:  #{format_rest_error(response)}"
      when Net::HTTPBadRequest
        ui.error "The data in your request was invalid"
        ui.info "Response: #{format_rest_error(response)}"
      when Net::HTTPNotFound
        ui.error "The object you are looking for could not be found"
        ui.info "Response: #{format_rest_error(response)}"
      when Net::HTTPInternalServerError
        ui.error "internal server error"
        ui.info "Response: #{format_rest_error(response)}"
      when Net::HTTPBadGateway
        ui.error "bad gateway"
        ui.info "Response: #{format_rest_error(response)}"
      when Net::HTTPServiceUnavailable
        ui.error "Service temporarily unavailable"
        ui.info "Response: #{format_rest_error(response)}"
      when Net::HTTPNotAcceptable
        version_header = Chef::JSONCompat.from_json(response["x-ops-server-api-version"])
        client_api_version = version_header["request_version"]
        min_server_version = version_header["min_version"]
        max_server_version = version_header["max_version"]
        ui.error "The API version that Knife is using is not supported by the server you sent this request to."
        ui.info "The request that Knife sent was using API version #{client_api_version}."
        ui.info "The server you sent the request to supports a min API version of #{min_server_version} and a max API version of #{max_server_version}."
        ui.info "Please either update your #{ChefUtils::Dist::Infra::PRODUCT} or the server to be a compatible set."
      else
        ui.error response.message
        ui.info "Response: #{format_rest_error(response)}"
      end
    end

    def username
      Chef::Config[:node_name]
    end

    def api_key
      Chef::Config[:client_key]
    end

    # Parses JSON from the error response sent by Chef Server and returns the
    # error message
    #--
    # TODO: this code belongs in Chef::REST
    def format_rest_error(response)
      Array(Chef::JSONCompat.from_json(response.body)["error"]).join("; ")
    rescue Exception
      response.body
    end

    # FIXME: yard with @yield
    def create_object(object, pretty_name = nil, object_class: nil)
      output = if object_class
                 edit_data(object, object_class: object_class)
               else
                 edit_hash(object)
               end

      if Kernel.block_given?
        output = yield(output)
      else
        output.save
      end

      pretty_name ||= output

      msg("Created #{pretty_name}")

      output(output) if config[:print_after]
    end

    # FIXME: yard with @yield
    def delete_object(klass, name, delete_name = nil)
      confirm("Do you really want to delete #{name}")

      if Kernel.block_given?
        object = yield
      else
        object = klass.load(name)
        object.destroy
      end

      output(format_for_display(object)) if config[:print_after]

      obj_name = delete_name ? "#{delete_name}[#{name}]" : object
      msg("Deleted #{obj_name}")
    end

    # helper method for testing if a field exists
    # and returning the usage and proper error if not
    def test_mandatory_field(field, fieldname)
      if field.nil?
        show_usage
        ui.fatal("You must specify a #{fieldname}")
        exit 1
      end
    end

    def rest
      @rest ||= Chef::ServerAPI.new(Chef::Config[:chef_server_url])
    end

    def noauth_rest
      @rest ||= begin
        require "chef/http/simple_json" unless defined?(Chef::HTTP::SimpleJSON)
        Chef::HTTP::SimpleJSON.new(Chef::Config[:chef_server_url])
      end
    end

    def server_url
      Chef::Config[:chef_server_url]
    end

    def maybe_setup_fips
      unless config[:fips].nil?
        Chef::Config[:fips] = config[:fips]
      end
    end

    def root_rest
      @root_rest ||= begin
        require "chef/server_api" unless defined? Chef::ServerAPI
        Chef::ServerAPI.new(Chef::Config[:chef_server_root])
      end
    end
  end
end
