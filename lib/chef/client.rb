#
# Author:: Adam Jacob (<adam@chef.io>)
# Author:: Christopher Walters (<cw@chef.io>)
# Author:: Christopher Brown (<cb@chef.io>)
# Author:: Tim Hinderliter (<tim@chef.io>)
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

require_relative "config"
require_relative "mixin/params_validate"
require "chef/mixin/powershell_exec"
require "chef/mixin/shell_out"
require "chef-utils/dsl/default_paths" unless defined?(ChefUtils::DSL::DefaultPaths)
require_relative "log"
require_relative "deprecated"
require_relative "server_api"
require_relative "api_client"
require_relative "api_client/registration"
require_relative "node"
require_relative "role"
require_relative "file_cache"
Chef.autoload :RunContext, File.expand_path("run_context", __dir__)
require_relative "runner"
require_relative "run_status"
require_relative "cookbook/cookbook_collection"
require_relative "cookbook/file_vendor"
require_relative "cookbook/file_system_file_vendor"
require_relative "cookbook/remote_file_vendor"
require_relative "event_dispatch/dispatcher"
require_relative "event_loggers/base"
require_relative "event_loggers/windows_eventlog"
require_relative "exceptions"
require_relative "formatters/base"
require_relative "formatters/doc"
require_relative "formatters/minimal"
require_relative "version"
require_relative "action_collection"
require_relative "resource_reporter"
require_relative "data_collector"
require_relative "run_lock"
Chef.autoload :PolicyBuilder, File.expand_path("policy_builder", __dir__)
require_relative "request_id"
require_relative "platform/rebooter"
require_relative "mixin/deprecation"
require "chef-utils" unless defined?(ChefUtils::CANARY)
require "ohai" unless defined?(Ohai::System)
require "rbconfig" unless defined?(RbConfig)
require "forwardable" unless defined?(Forwardable)

require_relative "compliance/runner"

class Chef
  # == Chef::Client
  # The main object in a Chef run. Preps a Chef::Node and Chef::RunContext,
  # syncs cookbooks if necessary, and triggers convergence.
  class Client
    extend Chef::Mixin::Deprecation
    include Chef::Mixin::PowershellExec
    include Chef::Mixin::ShellOut

    extend Forwardable
    #
    # The status of the Chef run.
    #
    # @return [Chef::RunStatus]
    #
    attr_reader :run_status

    #
    # The run context of the Chef run.
    #
    # @return [Chef::RunContext]
    #
    attr_reader :run_context

    #
    # The node represented by this client.
    #
    # @return [Chef::Node]
    #
    def node
      run_status.node
    end

    def node=(value)
      run_status.node = value
    end

    #
    # The ohai system used by this client.
    #
    # @return [Ohai::System]
    #
    attr_reader :ohai

    #
    # The runner used to converge.
    #
    # @return [Chef::Runner]
    #
    attr_accessor :runner

    #
    # Extra node attributes that were applied to the node.
    #
    # @return [Hash]
    #
    attr_reader :json_attribs

    #
    # The event dispatcher for the Chef run, including any configured output
    # formatters and event loggers.
    #
    # @return [EventDispatch::Dispatcher]
    #
    # @see Chef::Formatters
    # @see Chef::Config#formatters
    # @see Chef::Config#stdout
    # @see Chef::Config#stderr
    # @see Chef::Config#force_logger
    # @see Chef::Config#force_formatter
    # TODO add stdout, stderr, and default formatters to Chef::Config so the
    # defaults aren't calculated here.  Remove force_logger and force_formatter
    # from this code.
    # @see Chef::EventLoggers
    # @see Chef::Config#disable_event_logger
    # @see Chef::Config#event_loggers
    # @see Chef::Config#event_handlers
    #
    attr_reader :events

    attr_reader :logger

    def_delegator :@run_context, :transport_connection

    #
    # Creates a new Chef::Client.
    #
    # @param json_attribs [Hash] Node attributes to layer into the node when it is
    #   fetched.
    # @param args [Hash] Options:
    # @option args [Array<RunList::RunListItem>] :override_runlist A runlist to
    #   use instead of the node's embedded run list.
    # @option args [Array<String>] :specific_recipes A list of recipe file paths
    #   to load after the run list has been loaded.
    #
    def initialize(json_attribs = nil, args = {})
      @json_attribs = json_attribs || {}
      @logger = args.delete(:logger) || Chef::Log.with_child

      @ohai = Ohai::System.new(logger: logger)

      event_handlers = configure_formatters + configure_event_loggers
      event_handlers += Array(Chef::Config[:event_handlers])

      @events = EventDispatch::Dispatcher.new(*event_handlers)
      # @todo it seems like a bad idea to be deletin' other peoples' hashes.
      @override_runlist = args.delete(:override_runlist)
      @specific_recipes = args.delete(:specific_recipes)
      @run_status = Chef::RunStatus.new(nil, events)

      if new_runlist = args.delete(:runlist)
        @json_attribs["run_list"] = new_runlist
      end
    end

    #
    # Do a full run for this Chef::Client.
    #
    # Locks the run while doing its job.
    #
    # Fires run_start before doing anything and fires run_completed or
    # run_failed when finished.  Also notifies client listeners of run_started
    # at the beginning of Compile, and run_completed_successfully or run_failed
    # when all is complete.
    #
    # Phase 1: Setup
    # --------------
    # Gets information about the system and the run we are doing.
    #
    # 1. Run ohai to collect system information.
    # 2. Register / connect to the Chef server (unless in solo mode).
    # 3. Retrieve the node (or create a new one).
    # 4. Merge in json_attribs, Chef::Config.environment, and override_run_list.
    #
    # @see #run_ohai
    # @see #load_node
    # @see #build_node
    # @see Chef::Config#lockfile
    # @see Chef::RunLock#acquire
    #
    # Phase 2: Compile
    # ----------------
    # Decides *what* we plan to converge by compiling recipes.
    #
    # 1. Sync required cookbooks to the local cache.
    # 2. Load libraries from all cookbooks.
    # 3. Load attributes from all cookbooks.
    # 4. Load LWRPs from all cookbooks.
    # 5. Load resource definitions from all cookbooks.
    # 6. Load recipes in the run list.
    # 7. Load recipes from the command line.
    #
    # @see #setup_run_context Syncs and compiles cookbooks.
    # @see Chef::CookbookCompiler#compile
    #
    # Phase 3: Converge
    # -----------------
    # Brings the system up to date.
    #
    # 1. Converge the resources built from recipes in Phase 2.
    # 2. Save the node.
    # 3. Reboot if we were asked to.
    #
    # @see #converge_and_save
    # @see Chef::Runner
    #
    # @return Always returns true.
    #
    def run
      start_profiling

      runlock = RunLock.new(Chef::Config.lockfile)
      # TODO feels like acquire should have its own block arg for this
      runlock.acquire
      # don't add code that may fail before entering this section to be sure to release lock
      begin
        runlock.save_pid

        events.register(Chef::DataCollector::Reporter.new(events))
        events.register(Chef::ActionCollection.new(events))
        events.register(Chef::Compliance::Runner.new)

        run_status.run_id = request_id = Chef::RequestID.instance.request_id

        @run_context = Chef::RunContext.new
        run_context.events = events
        run_status.run_context = run_context

        events.run_start(Chef::VERSION, run_status)
        logger.info("*** #{ChefUtils::Dist::Infra::PRODUCT} #{Chef::VERSION} ***")
        logger.info("Platform: #{RUBY_PLATFORM}")
        logger.info "#{ChefUtils::Dist::Infra::CLIENT.capitalize} pid: #{Process.pid}"
        logger.info "Targeting node: #{Chef::Config.target_mode.host}" if Chef::Config.target_mode?
        logger.debug("#{ChefUtils::Dist::Infra::CLIENT.capitalize} request_id: #{request_id}")
        logger.warn("`enforce_path_sanity` is deprecated, please use `enforce_default_paths` instead!") if Chef::Config[:enforce_path_sanity]
        ENV["PATH"] = ChefUtils::DSL::DefaultPaths.default_paths if Chef::Config[:enforce_default_paths] || Chef::Config[:enforce_path_sanity]

        run_ohai

        unless Chef::Config[:solo_legacy_mode]
          register

          # create and save the rest objects in the run_context
          run_context.rest = rest
          run_context.rest_clean = rest_clean

          events.register(Chef::ResourceReporter.new(rest_clean))
        end

        load_node

        build_node

        run_status.start_clock
        logger.info("Starting #{ChefUtils::Dist::Infra::PRODUCT} Run for #{node.name}")
        run_started

        do_windows_admin_check

        Chef.resource_handler_map.lock!
        Chef.provider_handler_map.lock!

        setup_run_context

        load_required_recipe(@rest, run_context) unless Chef::Config[:solo_legacy_mode]

        converge_and_save(run_context)

        run_status.stop_clock
        logger.info("#{ChefUtils::Dist::Infra::PRODUCT} Run complete in #{run_status.elapsed_time} seconds")
        run_completed_successfully
        events.run_completed(node, run_status)

        # keep this inside the main loop to get exception backtraces
        end_profiling

        warn_if_eol

        # rebooting has to be the last thing we do, no exceptions.
        Chef::Platform::Rebooter.reboot_if_needed!(node)
      rescue Exception => run_error
        # CHEF-3336: Send the error first in case something goes wrong below and we don't know why
        logger.trace("Re-raising exception: #{run_error.class} - #{run_error.message}\n#{run_error.backtrace.join("\n  ")}")
        # If we failed really early, we may not have a run_status yet. Too early for these to be of much use.
        if run_status
          run_status.stop_clock
          run_status.exception = run_error
          run_failed
        end
        events.run_failed(run_error, run_status)
        Chef::Application.debug_stacktrace(run_error)
        raise run_error
      ensure
        Chef::RequestID.instance.reset_request_id
        @run_status = nil
        runlock.release
      end

      true
    end

    #
    # Private API
    # @todo make this stuff protected or private
    #

    # @api private
    def warn_if_eol
      require_relative "version"

      # We make a release every year so take the version you're on + 2006 and you get
      # the year it goes EOL
      eol_year = 2006 + Gem::Version.new(Chef::VERSION).segments.first

      if Time.now > Time.new(eol_year, 5, 01)
        logger.warn("This release of #{ChefUtils::Dist::Infra::PRODUCT} became end of life (EOL) on May 1st #{eol_year}. Please update to a supported release to receive new features, bug fixes, and security updates.")
      end
    end

    # @api private
    def configure_formatters
      formatters_for_run.map do |formatter_name, output_path|
        if output_path.nil?
          Chef::Formatters.new(formatter_name, STDOUT_FD, STDERR_FD)
        elsif output_path.is_a?(String)
          io = File.open(output_path, "a+")
          io.sync = true
          Chef::Formatters.new(formatter_name, io, io)
        end
      end
    end

    # @api private
    def formatters_for_run
      return Chef::Config.formatters unless Chef::Config.formatters.empty?

      [ Chef::Config[:log_location] ].flatten.map do |log_location|
        log_location = nil if log_location == STDOUT
        if !Chef::Config[:force_logger] || Chef::Config[:force_formatter]
          [:doc, log_location]
        else
          [:null]
        end
      end
    end

    # @api private
    def configure_event_loggers
      if Chef::Config.disable_event_logger
        []
      else
        Chef::Config.event_loggers.map do |evt_logger|
          case evt_logger
          when Symbol
            Chef::EventLoggers.new(evt_logger)
          when Class
            evt_logger.new
          else
          end
        end
      end
    end

    # Standard rest object for talking to the Chef Server
    #
    # FIXME: Can we drop this and only use the rest_clean object?  Did I add rest_clean
    # only out of some cant-break-a-minor-version paranoia?
    #
    # @api private
    def rest
      @rest ||= Chef::ServerAPI.new(Chef::Config[:chef_server_url], client_name: node_name,
                                    signing_key_filename: Chef::Config[:client_key])
    end

    # A rest object with validate_utf8 set to false.  This will not throw exceptions
    # on non-UTF8 strings in JSON but will sanitize them so that e.g. POSTs will
    # never fail.  Cannot be configured on a request-by-request basis, so we carry
    # around another rest object for it.
    #
    # @api private
    def rest_clean
      @rest_clean ||=
        Chef::ServerAPI.new(Chef::Config[:chef_server_url], client_name: node_name,
                            signing_key_filename: Chef::Config[:client_key], validate_utf8: false)
    end

    #
    # Callback to fire notifications that the Chef run is starting
    #
    # @api private
    #
    def run_started
      self.class.run_start_notifications.each do |notification|
        notification.call(run_status)
      end
      events.run_started(run_status)
    end

    #
    # Callback to fire notifications that the run completed successfully
    #
    # @api private
    #
    def run_completed_successfully
      success_handlers = self.class.run_completed_successfully_notifications
      success_handlers.each do |notification|
        notification.call(run_status)
      end
    end

    #
    # Callback to fire notifications that the Chef run failed
    #
    # @api private
    #
    def run_failed
      failure_handlers = self.class.run_failed_notifications
      failure_handlers.each do |notification|
        notification.call(run_status)
      end
    end

    #
    # Instantiates a Chef::Node object, possibly loading the node's prior state
    # when using chef-client. Sets Chef.node to the new node.
    #
    # @return [Chef::Node] The node object for this Chef run
    #
    # @see Chef::PolicyBuilder#load_node
    #
    # @api private
    #
    def load_node
      policy_builder.load_node
      run_status.node = policy_builder.node
      Chef.set_node(policy_builder.node)
      node
    end

    #
    # Mutates the `node` object to prepare it for the chef run.
    #
    # @return [Chef::Node] The updated node object
    #
    # @see Chef::PolicyBuilder#build_node
    #
    # @api private
    #
    def build_node
      policy_builder.build_node
      run_status.node = node
      node
    end

    #
    # Sync cookbooks to local cache.
    #
    # TODO this appears to be unused.
    #
    # @see Chef::PolicyBuilder#sync_cookbooks
    #
    # @api private
    #
    def sync_cookbooks
      policy_builder.sync_cookbooks
    end

    #
    # Sets up the run context.
    #
    # @see Chef::PolicyBuilder#setup_run_context
    #
    # @return The newly set up run context
    #
    # @api private
    def setup_run_context
      @run_context = policy_builder.setup_run_context(specific_recipes, run_context)
      assert_cookbook_path_not_empty(run_context)
      run_status.run_context = run_context # backcompat for chefspec
      run_context
    end

    #
    # Adds a required recipe as specified by the Chef Server
    #
    # @return The modified run context
    #
    # @api private
    #
    # TODO: @rest doesn't appear to be used anywhere outside
    # of client.register except for here. If it's common practice
    # to create your own rest client, perhaps we should do that
    # here but it seems more appropriate to reuse one that we
    # know is already created. for ease of testing, we'll pass
    # the existing rest client in as a parameter
    #
    def load_required_recipe(rest, run_context)
      required_recipe_contents = rest.get("required_recipe")
      logger.info("Required Recipe found, loading it")
      Chef::FileCache.store("required_recipe", required_recipe_contents)
      required_recipe_file = Chef::FileCache.load("required_recipe", false)

      # TODO: add integration tests with resource reporting turned on
      #       (presumably requires changes to chef-zero)
      #
      # Chef::Recipe.new takes a cookbook name and a recipe name along
      # with the run context. These names are eventually used in the
      # resource reporter, and if the cookbook name cannot be found in the
      # cookbook collection then we will fail with an exception. Cases where
      # we currently also fail:
      #   - specific recipes
      #   - chef-apply would fail if resource reporting was enabled
      #
      recipe = Chef::Recipe.new(nil, nil, run_context)
      recipe.from_file(required_recipe_file)
      run_context
    rescue Net::HTTPClientException => e
      case e.response
      when Net::HTTPNotFound
        logger.trace("Required Recipe not configured on the server, skipping it")
      else
        raise
      end
    end

    #
    # The PolicyBuilder strategy for figuring out run list and cookbooks.
    #
    # @return [Chef::PolicyBuilder::Policyfile, Chef::PolicyBuilder::ExpandNodeObject]
    #
    # @api private
    #
    def policy_builder
      @policy_builder ||= Chef::PolicyBuilder::Dynamic.new(node_name, ohai.data, json_attribs, override_runlist, events)
    end

    #
    # Save the updated node to Chef.
    #
    # Does not save if we are in solo mode or using override_runlist.
    #
    # @see Chef::Node#save
    # @see Chef::Config#solo
    #
    # @api private
    #
    def save_updated_node
      if Chef::Config[:solo_legacy_mode]
        # nothing to do
      elsif policy_builder.temporary_policy?
        logger.warn("Skipping final node save because override_runlist was given")
      else
        logger.debug("Saving the current state of node #{node_name}")
        node.save
      end
    end

    #
    # Run ohai plugins.  Runs all ohai plugins unless minimal_ohai is specified.
    #
    # Sends the ohai_completed event when finished.
    #
    # @see Chef::EventDispatcher#
    # @see Chef::Config#minimal_ohai
    #
    # @api private
    #
    def run_ohai
      filter = Chef::Config[:minimal_ohai] ? %w{fqdn machinename hostname platform platform_version ohai_time os os_version init_package} : nil
      ohai.transport_connection = transport_connection if Chef::Config.target_mode?
      ohai.all_plugins(filter)
      events.ohai_completed(node)
    end

    #
    # Figure out the node name we are working with.
    #
    # It tries these, in order:
    # - Chef::Config.node_name
    # - ohai[:fqdn]
    # - ohai[:machinename]
    # - ohai[:hostname]
    #
    # @raise [Chef::Exceptions::CannotDetermineNodeName] If the node name is not
    #   set and cannot be determined via ohai.
    #
    # @see Chef::Config#node_name
    #
    # @api private
    #
    def node_name
      name = Chef::Config[:node_name] || ohai[:fqdn] || ohai[:machinename] || ohai[:hostname]
      Chef::Config[:node_name] = name

      raise Chef::Exceptions::CannotDetermineNodeName unless name

      name
    end

    #
    # Determine our private key and set up the connection to the Chef server.
    #
    # Skips registration and fires the `skipping_registration` event if
    # Chef::Config.client_key is unspecified or already exists.
    #
    # If Chef::Config.client_key does not exist, we register the client with the
    # Chef server and fire the registration_start and registration_completed events.
    #
    # @return [Chef::ServerAPI] The server connection object.
    #
    # @see Chef::Config#chef_server_url
    # @see Chef::Config#client_key
    # @see Chef::ApiClient::Registration#run
    # @see Chef::EventDispatcher#skipping_registration
    # @see Chef::EventDispatcher#registration_start
    # @see Chef::EventDispatcher#registration_completed
    # @see Chef::EventDispatcher#registration_failed
    #
    # @api private
    #
    def register(client_name = node_name, config = Chef::Config)
      puts "\n cli.rb - This is the client name I am using : #{client_name}"
      puts "\n cli.rb - This is my client key : #{config[:client_key]}"
      if !config[:client_key]
        events.skipping_registration(client_name, config)
        logger.trace("Client key is unspecified - skipping registration")
      elsif detect_certificate_key(client_name)
        events.skipping_registration(client_name, config)
        logger.trace("Client key #{client_name} is present in certificate repository - skipping registration")
        puts "\n cli.rb - Did I correctly detect a client key in the certstore or keychain : #{detect_certificate_key(client_name)}"
        puts "\n cli.rb - Hey, I found an appropriate key in the keychain or Certstore!"
      elsif File.exist?(config[:client_key])
        events.skipping_registration(client_name, config)
        logger.trace("Client key #{config[:client_key]} is present - skipping registration")
      else
        puts "\n cli.rb - Did I correctly detect a client key in the certstore or keychain : #{detect_certificate_key(client_name)}"
        events.registration_start(node_name, config)
        logger.info("Client key #{config[:client_key]} is not present - registering")
        Chef::ApiClient::Registration.new(node_name, config[:client_key]).run
        events.registration_completed
      end
    rescue Exception => e
      # TODO this should probably only ever fire if we *started* registration.
      # Move it to the block above.
      # TODO: munge exception so a semantic failure message can be given to the
      # user
      events.registration_failed(client_name, e, config)
      raise
    end

    #
    # Detects if a private key exists in a certificate repository like Keychain (macOS) or Certificate Store (Windows)
    #
    # @param client_name - we're using the node name to store and retrieve any keys
    # Returns true if a key is found, false if not. False will trigger a registration event which will lead to a certificate based key being created
    #
    #
    def detect_certificate_key(client_name)
      if ChefUtils.windows?
        check_certstore_for_key(client_name)
      elsif ChefUtils.macos?
        puts "Made it to checking the macos key"
        check_keychain_for_key(client_name)
      else # generic return for Linux systemss
        false
      end
    end

    def check_certstore_for_key(client_name)
      powershell_code = <<~CODE
        $cert = Get-ChildItem -path cert:\\LocalMachine\\My -Recurse -Force  | Where-Object { $_.Subject -Match "#{client_name}" } -ErrorAction Stop
        if ($cert) {
          return $true
        }
        else{
          return $false
        }
      CODE
      powershell_exec!(powershell_code).result
    end

    # below we're checking Keychain for the presence of a cert.
    # We compare the output we get because the code throws an error (127) if the cert isn't present
    def check_keychain_for_key(client_name)
      mine = shell_out! <<~EOH
      getcert() {
          CERTSTATUS=$(security find-certificate -c #{client_name} >/dev/null)
          SUB='#{client_name}'
          if [[ "$CERTSTATUS" == *"$SUB"* ]]; then
              true
          else
              false
          fi
      }
      getcert
      getcertresult=$?
      echo $getcertresult
      EOH

      # The bash script above checks for a cert in Keychain and returns a 127 if not present, 0 if present.
      output = mine.run_command
      output == '0' ? true : false
    end

    #
    # Converges all compiled resources.
    #
    # Fires the converge_start, converge_complete and converge_failed events.
    #
    # If the exception `:end_client_run_early` is thrown during convergence, it
    # does not mark the run complete *or* failed, and returns `nil`
    #
    # @param run_context The run context.
    #
    # @raise Any converge exception
    #
    # @see Chef::Runner#converge
    # @see Chef::EventDispatch#converge_start
    # @see Chef::EventDispatch#converge_complete
    # @see Chef::EventDispatch#converge_failed
    #
    # @api private
    #
    def converge(run_context)
      catch(:end_client_run_early) do

        events.converge_start(run_context)
        logger.debug("Converging node #{node_name}")
        @runner = Chef::Runner.new(run_context)
        @runner.converge
        events.converge_complete
      rescue Exception => e
        events.converge_failed(e)
        raise e

      end
    end

    # Converge the node via and then save it if successful.
    #
    # If converge() raises it is important that save_updated_node is bypassed.
    #
    # @param run_context [Chef::RunContext] The run context.
    # @raise Any converge or node save exception
    #
    # @api private
    #
    def converge_and_save(run_context)
      converge(run_context)
      save_updated_node
    end

    #
    # Expands the run list.
    #
    # @return [Chef::RunListExpansion] The expanded run list.
    #
    # @see Chef::PolicyBuilder#expand_run_list
    #
    def expanded_run_list
      policy_builder.expand_run_list
    end

    #
    # Check if the user has Administrator privileges on windows.
    #
    # Throws an error if the user is not an admin, and
    # `Chef::Config.fatal_windows_admin_check` is true.
    #
    # @raise [Chef::Exceptions::WindowsNotAdmin] If the user is not an admin.
    #
    # @see Chef::platform#windows?
    # @see Chef::Config#fatal_windows_admin_check
    #
    # @api private
    #
    def do_windows_admin_check
      if ChefUtils.windows?
        logger.trace("Checking for administrator privileges....")

        if !has_admin_privileges?
          message = "#{ChefUtils::Dist::Infra::CLIENT} doesn't have administrator privileges on node #{node_name}."
          if Chef::Config[:fatal_windows_admin_check]
            logger.fatal(message)
            logger.fatal("fatal_windows_admin_check is set to TRUE.")
            raise Chef::Exceptions::WindowsNotAdmin, message
          else
            logger.warn("#{message} This might cause unexpected resource failures.")
          end
        else
          logger.trace("#{ChefUtils::Dist::Infra::CLIENT} has administrator privileges on node #{node_name}.")
        end
      end
    end

    # Notification registration
    class<<self
      #
      # Add a listener for the 'client run started' event.
      #
      # @param notification_block The callback (takes |run_status| parameter).
      # @yieldparam [Chef::RunStatus] run_status The run status.
      #
      def when_run_starts(&notification_block)
        run_start_notifications << notification_block
      end

      #
      # Add a listener for the 'client run success' event.
      #
      # @param notification_block The callback (takes |run_status| parameter).
      # @yieldparam [Chef::RunStatus] run_status The run status.
      #
      def when_run_completes_successfully(&notification_block)
        run_completed_successfully_notifications << notification_block
      end

      #
      # Add a listener for the 'client run failed' event.
      #
      # @param notification_block The callback (takes |run_status| parameter).
      # @yieldparam [Chef::RunStatus] run_status The run status.
      #
      def when_run_fails(&notification_block)
        run_failed_notifications << notification_block
      end

      #
      # Clears all listeners for client run status events.
      #
      # Primarily for testing purposes.
      #
      # @api private
      #
      def clear_notifications
        @run_start_notifications = nil
        @run_completed_successfully_notifications = nil
        @run_failed_notifications = nil
      end

      #
      # TODO These seem protected to me.
      #

      #
      # Listeners to be run when the client run starts.
      #
      # @return [Array<Proc>]
      #
      # @api private
      #
      def run_start_notifications
        @run_start_notifications ||= []
      end

      #
      # Listeners to be run when the client run completes successfully.
      #
      # @return [Array<Proc>]
      #
      # @api private
      #
      def run_completed_successfully_notifications
        @run_completed_successfully_notifications ||= []
      end

      #
      # Listeners to be run when the client run fails.
      #
      # @return [Array<Proc>]
      #
      # @api private
      #
      def run_failed_notifications
        @run_failed_notifications ||= []
      end
    end

    #
    # IO stream that will be used as 'STDOUT' for formatters. Formatters are
    # configured during `initialize`, so this provides a convenience for
    # setting alternative IO stream during tests.
    #
    # @api private
    #
    STDOUT_FD = STDOUT

    #
    # IO stream that will be used as 'STDERR' for formatters. Formatters are
    # configured during `initialize`, so this provides a convenience for
    # setting alternative IO stream during tests.
    #
    # @api private
    #
    STDERR_FD = STDERR

    private

    attr_reader :override_runlist
    attr_reader :specific_recipes

    def profiling_prereqs!
      require "ruby-prof"
    rescue LoadError => e
      raise "You must have the ruby-prof gem installed in order to use --profile-ruby: #{e.message}"
    end

    def start_profiling
      return unless Chef::Config[:profile_ruby]

      profiling_prereqs!
      RubyProf.start
    end

    def end_profiling
      return unless Chef::Config[:profile_ruby]

      profiling_prereqs!
      path = Chef::FileCache.create_cache_path("graph_profile.out", false)
      File.open(path, "w+") do |file|
        RubyProf::GraphPrinter.new(RubyProf.stop).print(file, {})
      end
      logger.warn("Ruby execution profile dumped to #{path}")
    end

    def empty_directory?(path)
      !File.exists?(path) || (Dir.entries(path).size <= 2)
    end

    def is_last_element?(index, object)
      object.is_a?(Array) ? index == object.size - 1 : true
    end

    def assert_cookbook_path_not_empty(run_context)
      if Chef::Config[:solo_legacy_mode]
        # Check for cookbooks in the path given
        # Chef::Config[:cookbook_path] can be a string or an array
        # if it's an array, go through it and check each one, raise error at the last one if no files are found
        cookbook_paths = Array(Chef::Config[:cookbook_path])
        logger.trace "Loading from cookbook_path: #{cookbook_paths.map { |path| File.expand_path(path) }.join(", ")}"
        if cookbook_paths.all? { |path| empty_directory?(path) }
          msg = "None of the cookbook paths set in Chef::Config[:cookbook_path], #{cookbook_paths.inspect}, contain any cookbooks"
          logger.fatal(msg)
          raise Chef::Exceptions::CookbookNotFound, msg
        end
      else
        logger.warn("Node #{node_name} has an empty run list.") if run_context.node.run_list.empty?
      end
    end

    def has_admin_privileges?
      require_relative "win32/security"

      Chef::ReservedNames::Win32::Security.has_admin_privileges?
    end
  end
end

# HACK cannot load this first, but it must be loaded.
require_relative "cookbook_loader"
require_relative "cookbook_version"
require_relative "cookbook/synchronizer"
