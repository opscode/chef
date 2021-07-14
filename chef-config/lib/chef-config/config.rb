#
# Author:: Adam Jacob (<adam@chef.io>)
# Author:: Christopher Brown (<cb@chef.io>)
# Author:: AJ Christensen (<aj@chef.io>)
# Author:: Mark Mzyk (<mmzyk@chef.io>)
# Author:: Kyle Goodwin (<kgoodwin@primerevenue.com>)
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

require "mixlib/config" unless defined?(Mixlib::Config)
autoload :Pathname, "pathname"
autoload :ChefUtils, "chef-utils"

require_relative "fips"
require_relative "logger"
require_relative "windows"
require_relative "path_helper"
require_relative "mixin/fuzzy_hostname_matcher"

module Mixlib
  autoload :ShellOut, "mixlib/shellout"
end
autoload :URI, "uri"
module Addressable
  autoload :URI, "addressable/uri"
end
autoload :OpenSSL, "openssl"
autoload :YAML, "yaml"
require "chef-utils/dist" unless defined?(ChefUtils::Dist)

module ChefConfig

  class Config

    extend Mixlib::Config
    extend ChefConfig::Mixin::FuzzyHostnameMatcher

    # Evaluates the given string as config.
    #
    # +filename+ is used for context in stacktraces, but doesn't need to be the name of an actual file.
    def self.from_string(string, filename)
      instance_eval(string, filename, 1)
    end

    def self.inspect
      configuration.inspect
    end

    # given a *nix style config path return the platform specific path
    # to that same config file
    # @example client.pem path on Windows
    #   platform_specific_path("/etc/chef/client.pem") #=> "C:\\chef\\client.pem"
    # @param path [String] The unix path to convert to a platform specific path
    # @return [String] a platform specific path
    def self.platform_specific_path(path)
      path = PathHelper.cleanpath(path)
      if ChefUtils.windows?
        # turns \etc\chef\client.rb and \var\chef\client.rb into C:/chef/client.rb
        # Some installations will be on different drives so use the drive that
        # the expanded path to __FILE__ is found.
        drive = windows_installation_drive
        if drive && path[0] == "\\" && path.split("\\")[2] == "chef"
          path = PathHelper.join(drive, path.split("\\", 3)[2])
        end
      end
      path
    end

    # On *nix, /etc/chef, on Windows C:\chef
    #
    # @param windows [Boolean] optional flag to force to windows or unix-style
    # @return [String] the platform-specific path
    #
    def self.etc_chef_dir(windows: ChefUtils.windows?)
      path = windows ? c_chef_dir : PathHelper.join("/etc", ChefUtils::Dist::Infra::DIR_SUFFIX, windows: windows)
      PathHelper.cleanpath(path, windows: windows)
    end

    # On *nix, /var/chef, on Windows C:\chef
    #
    # @param windows [Boolean] optional flag to force to windows or unix-style
    # @return [String] the platform-specific path
    #
    def self.var_chef_dir(windows: ChefUtils.windows?)
      path = windows ? c_chef_dir : PathHelper.join("/var", ChefUtils::Dist::Infra::DIR_SUFFIX, windows: windows)
      PathHelper.cleanpath(path, windows: windows)
    end

    # On *nix, /var, on Windows C:\
    #
    # @param windows [Boolean] optional flag to force to windows or unix-style
    # @return [String] the platform-specific path
    #
    def self.var_root_dir(windows: ChefUtils.windows?)
      path = windows ? "C:\\" : "/var"
      PathHelper.cleanpath(path, windows: windows)
    end

    # On windows, C:/chef/
    #
    # (should only be called in a windows-context)
    #
    # @return [String] the platform-specific path
    #
    def self.c_chef_dir(windows: ChefUtils.windows?)
      drive = windows_installation_drive || "C:"
      PathHelper.join(drive, ChefUtils::Dist::Infra::DIR_SUFFIX, windows: windows)
    end

    # On windows, C:/opscode
    #
    # (should only be called in a windows-context)
    #
    # @return [String] the platform-specific path
    #
    def self.c_opscode_dir(windows: ChefUtils.windows?)
      drive = windows_installation_drive || "C:"
      PathHelper.join(drive, ChefUtils::Dist::Org::LEGACY_CONF_DIR, ChefUtils::Dist::Infra::DIR_SUFFIX, windows: windows)
    end

    # the drive where Chef is installed on a windows host. This is determined
    # either by the drive containing the current file or by the SYSTEMDRIVE ENV
    # variable
    #
    # (should only be called in a windows-context)
    #
    # @return [String] the drive letter
    #
    def self.windows_installation_drive
      if ChefUtils.windows?
        drive = File.expand_path(__FILE__).split("/", 2)[0]
        drive = ENV["SYSTEMDRIVE"] if drive.to_s == ""
        drive
      end
    end

    # @param name [String]
    # @param file_path [String]
    def self.add_formatter(name, file_path = nil)
      formatters << [name, file_path]
    end

    # @param logger [String]
    def self.add_event_logger(logger)
      event_handlers << logger
    end

    def self.apply_extra_config_options(extra_config_options)
      if extra_config_options
        extra_parsed_options = extra_config_options.inject({}) do |memo, option|
          # Sanity check value.
          if option.empty? || !option.include?("=")
            raise UnparsableConfigOption, "Unparsable config option #{option.inspect}"
          end

          # Split including whitespace if someone does truly odd like
          # --config-option "foo = bar"
          key, value = option.split(/\s*=\s*/, 2)

          # Call to_sym because Chef::Config expects only symbol keys. Also
          # runs a simple parse on the string for some common types.
          memo[key.to_sym] = YAML.safe_load(value)
          memo
        end
        set_extra_config_options(extra_parsed_options)
      end
    end

    # We use :[]= assignment here to not bypass any coercions that happen via mixlib-config writes_value callbacks
    def self.set_extra_config_options(extra_parsed_options)
      extra_parsed_options.each do |key, value|
        self[key.to_sym] = value
      end
    end

    # Config file to load (client.rb, knife.rb, etc. defaults set differently in knife, chef-client, etc.)
    configurable(:config_file)

    default(:config_dir) do
      if config_file
        PathHelper.dirname(PathHelper.canonical_path(config_file, false))
      else
        PathHelper.join(PathHelper.cleanpath(user_home), ChefUtils::Dist::Infra::USER_CONF_DIR, "")
      end
    end

    default :formatters, []

    # @param uri [String] the URI to validate
    #
    # @return [Boolean] is the URL valid
    def self.is_valid_url?(uri)
      url = uri.to_s.strip
      %r{^http://} =~ url || %r{^https://} =~ url || /^chefzero:/ =~ url
    end

    # Override the config dispatch to set the value of multiple server options simultaneously
    #
    # @param [String] url String to be set for all of the chef-server-api URL's
    #
    configurable(:chef_server_url).writes_value do |uri|
      unless is_valid_url? uri
        raise ConfigurationError, "#{uri} is an invalid chef_server_url. The URL must start with http://, https://, or chefzero://."
      end

      uri.to_s.strip
    end

    # When you are using ActiveSupport, they monkey-patch 'daemonize' into Kernel.
    # So while this is basically identical to what method_missing would do, we pull
    # it up here and get a real method written so that things get dispatched
    # properly.
    configurable(:daemonize).writes_value { |v| v }

    def self.expand_relative_paths(path)
      unless path.nil?
        if path.is_a?(String)
          File.expand_path(path)
        else
          Array(path).map { |path| File.expand_path(path) }
        end
      end
    end

    configurable(:cookbook_path).writes_value { |path| expand_relative_paths(path) }

    configurable(:chef_repo_path).writes_value { |path| expand_relative_paths(path) }

    # The root where all local chef object data is stored.  cookbooks, data bags,
    # environments are all assumed to be in separate directories under this.
    # chef-solo uses these directories for input data.  knife commands
    # that upload or download files (such as knife upload, knife role from file,
    # etc.) work.
    default :chef_repo_path do
      if configuration[:cookbook_path]
        if configuration[:cookbook_path].is_a?(String)
          File.expand_path("..", configuration[:cookbook_path])
        else
          configuration[:cookbook_path].map do |path|
            File.expand_path("..", path)
          end
        end
      elsif configuration[:cookbook_artifact_path]
        File.expand_path("..", configuration[:cookbook_artifact_path])
      else
        cache_path
      end
    end

    def self.find_chef_repo_path(cwd)
      # In local mode, we auto-discover the repo root by looking for a path with "cookbooks" under it.
      # This allows us to run config-free.
      path = cwd
      until File.directory?(PathHelper.join(path, "cookbooks")) || File.directory?(PathHelper.join(path, "cookbook_artifacts"))
        new_path = File.expand_path("..", path)
        if new_path == path
          ChefConfig.logger.warn("No cookbooks directory found at or above current directory.  Assuming #{cwd}.")
          return cwd
        end
        path = new_path
      end
      ChefConfig.logger.info("Auto-discovered #{ChefUtils::Dist::Infra::SHORT} repository at #{path}")
      path
    end

    # @param child_path [String]
    def self.derive_path_from_chef_repo_path(child_path)
      if chef_repo_path.is_a?(String)
        PathHelper.join(chef_repo_path, child_path)
      else
        chef_repo_path.uniq.map { |path| PathHelper.join(path, child_path) }
      end
    end

    # Location of acls on disk. String or array of strings.
    # Defaults to <chef_repo_path>/acls.
    default(:acl_path) { derive_path_from_chef_repo_path("acls") }.writes_value { |path| expand_relative_paths(path) }

    # Location of clients on disk. String or array of strings.
    # Defaults to <chef_repo_path>/clients.
    default(:client_path) { derive_path_from_chef_repo_path("clients") }.writes_value { |path| expand_relative_paths(path) }

    # Location of client keys on disk. String or array of strings.
    # Defaults to <chef_repo_path>/client_keys.
    default(:client_key_path) { derive_path_from_chef_repo_path("client_keys") }.writes_value { |path| expand_relative_paths(path) }

    # Location of containers on disk. String or array of strings.
    # Defaults to <chef_repo_path>/containers.
    default(:container_path) { derive_path_from_chef_repo_path("containers") }.writes_value { |path| expand_relative_paths(path) }

    # Location of cookbook_artifacts on disk. String or array of strings.
    # Defaults to <chef_repo_path>/cookbook_artifacts.
    default(:cookbook_artifact_path) { derive_path_from_chef_repo_path("cookbook_artifacts") }.writes_value { |path| expand_relative_paths(path) }

    # Location of cookbooks on disk. String or array of strings.
    # Defaults to <chef_repo_path>/cookbooks.  If chef_repo_path
    # is not specified, this is set to /var/chef/cookbooks.
    default(:cookbook_path) { derive_path_from_chef_repo_path("cookbooks") }

    # Location of data bags on disk. String or array of strings.
    # Defaults to <chef_repo_path>/data_bags.
    default(:data_bag_path) { derive_path_from_chef_repo_path("data_bags") }.writes_value { |path| expand_relative_paths(path) }

    # Location of environments on disk. String or array of strings.
    # Defaults to <chef_repo_path>/environments.
    default(:environment_path) { derive_path_from_chef_repo_path("environments") }.writes_value { |path| expand_relative_paths(path) }

    # Location of groups on disk. String or array of strings.
    # Defaults to <chef_repo_path>/groups.
    default(:group_path) { derive_path_from_chef_repo_path("groups") }.writes_value { |path| expand_relative_paths(path) }

    # Location of nodes on disk. String or array of strings.
    # Defaults to <chef_repo_path>/nodes.
    default(:node_path) { derive_path_from_chef_repo_path("nodes") }.writes_value { |path| expand_relative_paths(path) }

    # Location of policies on disk. String or array of strings.
    # Defaults to <chef_repo_path>/policies.
    default(:policy_path) { derive_path_from_chef_repo_path("policies") }.writes_value { |path| expand_relative_paths(path) }

    # Location of policy_groups on disk. String or array of strings.
    # Defaults to <chef_repo_path>/policy_groups.
    default(:policy_group_path) { derive_path_from_chef_repo_path("policy_groups") }.writes_value { |path| expand_relative_paths(path) }

    # Location of roles on disk. String or array of strings.
    # Defaults to <chef_repo_path>/roles.
    default(:role_path) { derive_path_from_chef_repo_path("roles") }.writes_value { |path| expand_relative_paths(path) }

    # Location of users on disk. String or array of strings.
    # Defaults to <chef_repo_path>/users.
    default(:user_path) { derive_path_from_chef_repo_path("users") }.writes_value { |path| expand_relative_paths(path) }

    # DEPRECATED
    default :enforce_path_sanity, false

    # Enforce default paths by default for all APIs, not just the default internal shell_out
    default :enforce_default_paths, false

    # Formatted Chef Client output is a beta feature, disabled by default:
    default :formatter, "null"

    # The number of times the client should retry when registering with the server
    default :client_registration_retries, 5

    # An array of paths to search for knife exec scripts if they aren't in the current directory
    default :script_path, []

    # The root of all caches (checksums, cache and backup).  If local mode is on,
    # this is under the user's home directory.
    default(:cache_path) do
      if local_mode
        PathHelper.join(config_dir, "local-mode-cache")
      else
        primary_cache_root = var_root_dir
        primary_cache_path = var_chef_dir
        # Use /var/chef as the cache path only if that folder exists and we can read and write
        # into it, or /var exists and we can read and write into it (we'll create /var/chef later).
        # Otherwise, we'll create .chef under the user's home directory and use that as
        # the cache path.
        unless path_accessible?(primary_cache_path) || path_accessible?(primary_cache_root)
          secondary_cache_path = PathHelper.join(user_home, ChefUtils::Dist::Infra::USER_CONF_DIR)
          secondary_cache_path = target_mode? ? PathHelper.join(secondary_cache_path, target_mode.host) : secondary_cache_path
          ChefConfig.logger.trace("Unable to access cache at #{primary_cache_path}. Switching cache to #{secondary_cache_path}")
          secondary_cache_path
        else
          target_mode? ? PathHelper.join(primary_cache_path, target_mode.host) : primary_cache_path
        end
      end
    end

    # Returns true only if the path exists and is readable and writeable for the user.
    #
    # @param path [String]
    def self.path_accessible?(path)
      File.exist?(path) && File.readable?(path) && File.writable?(path)
    end

    # Where cookbook files are stored on the server (by content checksum)
    default(:checksum_path) { PathHelper.join(cache_path, "checksums") }

    # Where chef's cache files should be stored
    default(:file_cache_path) { PathHelper.join(cache_path, "cache") }.writes_value { |path| expand_relative_paths(path) }

    # Where chef's cache files should be stored, used for bootstrap on unix filesystems
    default(:unix_bootstrap_file_cache_path) { PathHelper.join("/var", ChefUtils::Dist::Infra::DIR_SUFFIX, "cache", windows: false) }

    # Where chef's cache files should be stored, used for bootstrap on windows filesystems
    default(:windows_bootstrap_file_cache_path) { PathHelper.join("C:", ChefUtils::Dist::Infra::DIR_SUFFIX, "cache", windows: true) }

    # Where backups of chef-managed files should go
    default(:file_backup_path) { PathHelper.join(cache_path, "backup") }

    # Where chef's backup files should be stored, used for bootstrap on unix filesystems
    default(:unix_bootstrap_file_backup_path) { PathHelper.join("/var", ChefUtils::Dist::Infra::DIR_SUFFIX, "backup", windows: false) }

    # Where chef's backup files should be stored, used for bootstrap on windows filesystems
    default(:windows_bootstrap_file_backup_path) { PathHelper.join("C:", ChefUtils::Dist::Infra::DIR_SUFFIX, "backup", windows: true) }

    # The chef-client (or solo) lockfile.
    #
    # If your `file_cache_path` resides on a NFS (or non-flock()-supporting
    # fs), it's recommended to set this to something like
    # '/tmp/chef-client-running.pid'
    default(:lockfile) { PathHelper.join(file_cache_path, "#{ChefUtils::Dist::Infra::CLIENT}-running.pid") }

    ## Daemonization Settings ##
    # What user should Chef run as?
    default :user, nil
    default :group, nil
    default :umask, 0022

    # Valid log_levels are:
    # * :trace
    # * :debug
    # * :info
    # * :warn
    # * :fatal
    # These work as you'd expect. There is also a special `:auto` setting.
    # When set to :auto, Chef will auto adjust the log verbosity based on
    # context. When a tty is available (usually because the user is running chef
    # in a console), the log level is set to :warn, and output formatters are
    # used as the primary mode of output. When a tty is not available, the
    # logger is the primary mode of output, and the log level is set to :info
    default :log_level, :auto

    # Logging location as either an IO stream or string representing log file path
    default :log_location, nil

    # Using `force_formatter` causes chef to default to formatter output when STDOUT is not a tty
    default :force_formatter, false

    # Using `force_logger` causes chef to default to logger output when STDOUT is a tty
    default :force_logger, false

    # When set to true always print the stacktrace even if we haven't done -l debug
    default :always_dump_stacktrace, false

    # Using 'stream_execute_output' will have Chef always stream the execute output
    default :stream_execute_output, false

    # Using `show_download_progress` will display the overall progress
    # of a remote file download
    default :show_download_progress, false
    # How often to update the progress meter, in percent
    default :download_progress_interval, 10

    default :http_retry_count, 5
    default :http_retry_delay, 5
    # Whether or not to send the Authorization header again on http redirects.
    # As per the plan in https://github.com/chef/chef/pull/7006, this will be
    # False in Chef 14, True in Chef 15, and will be removed entirely in Chef 16.
    default :http_disable_auth_on_redirect, true

    default :interval, nil
    default :once, nil
    default :json_attribs, nil
    # toggle info level log items that can create a lot of output
    default :verbose_logging, true
    default :node_name, nil
    default :diff_disabled,           false
    default :diff_filesize_threshold, 10000000
    default :diff_output_threshold,   1000000

    # This is true for "local mode" which uses a chef-zero server listening on
    # localhost one way or another.  This is true for both `chef-solo` (without
    # the --legacy-mode flag) or `chef-client -z` methods of starting a client run.
    #
    default :local_mode, false

    # Configures the mode of operation for ChefFS, which is applied to the
    # ChefFS-based knife commands and chef-client's local mode. (ChefFS-based
    # knife commands include: knife delete, knife deps, knife diff, knife down,
    # knife edit, knife list, knife show, knife upload, and knife xargs.)
    #
    # Valid values are:
    # * "static": ChefFS only manages objects that exist in a traditional Chef
    #   Repo as of Chef 11.
    # * "everything": ChefFS manages all object types that existed on the OSS
    #   Chef 11 server.
    # * "hosted_everything": ChefFS manages all object types as of the Chef 12
    #   Server, including RBAC objects and Policyfile objects (new to Chef 12).
    default :repo_mode do
      if local_mode && !chef_zero.osc_compat
        "hosted_everything"
      elsif %r{/+organizations/.+}.match?(chef_server_url)
        "hosted_everything"
      else
        "everything"
      end
    end

    default :pid_file, nil

    # Whether Chef Zero local mode should bind to a port. All internal requests
    # will go through the socketless code path regardless, so the socket is
    # only needed if other processes will connect to the local mode server.
    default :listen, false

    config_context :chef_zero do
      config_strict_mode true
      default(:enabled) { ChefConfig::Config.local_mode }
      default :host, "localhost"
      default :port, 8889.upto(9999) # Will try ports from 8889-9999 until one works

      # When set to a String, Chef Zero disables multitenant support.  This is
      # what you want when using Chef Zero to serve a single Chef Repo. Setting
      # this to `false` enables multi-tenant.
      default :single_org, "chef"

      # Whether Chef Zero should operate in a mode analogous to OSS Chef Server
      # 11 (true) or Chef Server 12 (false). Chef Zero can still serve
      # policyfile objects in Chef 11 mode, as long as `repo_mode` is set to
      # "hosted_everything". The primary differences are:
      # * Chef 11 mode doesn't support multi-tenant, so there is no
      #   distinction between global and org-specific objects (since there are
      #   no orgs).
      # * Chef 11 mode doesn't expose RBAC objects
      default :osc_compat, false
    end

    # RFCxxx Target Mode support, value is the name of a remote device to Chef against
    # --target exists as a shortcut to enabling target_mode and setting the host
    configurable(:target)

    config_context :target_mode do
      config_strict_mode false # we don't want to have to add all train configuration keys here
      default :enabled, false
      default :protocol, "ssh"
      # typical additional keys: host, user, password
    end

    def self.target_mode?
      target_mode.enabled
    end

    default :chef_server_url, "https://localhost:443"

    default(:chef_server_root) do
      # if the chef_server_url is a path to an organization, aka
      # 'some_url.../organizations/*' then remove the '/organization/*' by default
      if %r{/organizations/\S*$}.match?(configuration[:chef_server_url])
        configuration[:chef_server_url].split("/")[0..-3].join("/")
      elsif configuration[:chef_server_url] # default to whatever chef_server_url is
        configuration[:chef_server_url]
      else
        "https://localhost:443"
      end
    end

    default :rest_timeout, 300

    # This solo setting is now almost entirely useless.  It is set to true if chef-solo was
    # invoked that way from the command-line (i.e. from Application::Solo as opposed to
    # Application::Client).  The more useful information is contained in the :solo_legacy_mode
    # vs the :local_mode flags which will be set to true or false depending on how solo was
    # invoked and actually change more of the behavior.  There might be slight differences in
    # the behavior of :local_mode due to the behavioral differences in Application::Solo vs.
    # Application::Client and `chef-solo` vs `chef-client -z`, but checking this value and
    # switching based on it is almost certainly doing the wrong thing and papering over
    # bugs that should be fixed in one or the other class, and will be brittle and destined
    # to break in the future (and not necessarily on a major version bump). Checking this value
    # is also not sufficient to determine if we are not running against a server since this can
    # be unset but :local_mode may be set.  It would be accurate to check both :solo and :local_mode
    # to determine if we're not running against a server, but the more semantically accurate test
    # is going to be combining :solo_legacy_mode and :local_mode.
    #
    # TL;DR: `if Chef::Config[:solo]` is almost certainly buggy code, you should use:
    #        `if Chef::Config[:local_mode] || Chef::Config[:solo_legacy_mode]`
    #
    # @api private
    default :solo, false

    # This is true for old chef-solo legacy mode without any chef-zero server (chef-solo --legacy-mode)
    default :solo_legacy_mode, false

    default :splay, nil
    default :why_run, false
    default :color, false
    default :client_fork, nil
    default :ez, false
    default :enable_reporting, true
    default :enable_reporting_url_fatals, false

    # Chef only needs ohai to run the hostname plugin for the most basic
    # functionality. If the rest of the ohai plugins are not needed (like in
    # most of our testing scenarios)
    default :minimal_ohai, false

    # When consuming Ohai plugins from cookbook segments, we place those plugins in this directory.
    # Subsequent chef client runs will wipe and re-populate the directory to ensure cleanliness
    default(:ohai_segment_plugin_path) { PathHelper.join(config_dir, "ohai", "cookbook_plugins") }

    ###
    # Policyfile Settings
    #
    # Policyfile is a feature where a node gets its run list and cookbook
    # version set from a single document on the server instead of expanding the
    # run list and having the server compute the cookbook version set based on
    # environment constraints.
    #
    # Policyfiles are auto-versioned. The user groups nodes by `policy_name`,
    # which generally describes a hosts's functional role, and `policy_group`,
    # which generally groups nodes by deployment phase (a.k.a., "environment").
    # The Chef Server maps a given set of `policy_name` plus `policy_group` to
    # a particular revision of a policy.

    default :policy_name, nil
    default :policy_group, nil

    # Policyfiles can have multiple run lists, via the named run list feature.
    # Generally this will be set by a CLI option via Chef::Application::Client,
    # but it could be set in client.rb if desired.

    default :named_run_list, nil

    # Policyfiles can be used in a native mode (default) or compatibility mode.
    # Native mode requires Chef Server 12.1 (it can be enabled via feature flag
    # on some prior versions). In native mode, policies and associated
    # cookbooks are accessed via feature-specific APIs. In compat mode,
    # policies are stored as data bags and cookbooks are stored at the
    # cookbooks/ endpoint. Compatibility mode can be dangerous on existing Chef
    # Servers; it's recommended to upgrade your Chef Server rather than use
    # compatibility mode. Compatibility mode remains available so you can use
    # policyfiles with servers that don't yet support the native endpoints.
    default :policy_document_native_api, true

    # When policyfiles are used in compatibility mode, `policy_name` and
    # `policy_group` are instead specified using a combined configuration
    # setting, `deployment_group`. For example, if policy_name should be
    # "webserver" and policy_group should be "staging", then `deployment_group`
    # should be set to "webserver-staging", which is the name of the data bag
    # item that the policy will be stored as. NOTE: this setting only has an
    # effect if `policy_document_native_api` is set to `false`.
    default :deployment_group, nil

    # When using policyfiles you can optionally set it to read the node.run_list
    # from the server and have that override the policyfile run_list or the
    # named_run_list set in config.  With policyfiles there is no depsolving done
    # on the run_list items so every item in the run_list must be in the set of
    # cookbooks pushed to the node.  This enables flows where the node can change
    # its run_list and have it persist or to bootstrap nodes with the -j flag.  If
    # no run_list is set on the server node object then the configured named_run_list
    # or run_list out of the policy is used.
    default :policy_persist_run_list, false

    # Set these to enable SSL authentication / mutual-authentication
    # with the server

    # Client side SSL cert/key for mutual auth
    default :ssl_client_cert, nil
    default :ssl_client_key, nil

    # Whether or not to verify the SSL cert for all HTTPS requests. When set to
    # :verify_peer (default), all HTTPS requests will be validated regardless of other
    # SSL verification settings. When set to :verify_none no HTTPS requests will
    # be validated.
    default :ssl_verify_mode, :verify_peer

    # Needed to coerce string value to a symbol when loading settings from the
    # credentials toml files which doesn't allow ruby symbol values
    configurable(:ssl_verify_mode).writes_value do |value|
      if value.is_a?(String) && value[0] == ":"
        value[1..].to_sym
      else
        value.to_sym
      end
    end

    # Whether or not to verify the SSL cert for HTTPS requests to the Chef
    # server API. If set to `true`, the server's cert will be validated
    # regardless of the :ssl_verify_mode setting. This is set to `true` when
    # running in local-mode.
    # NOTE: This is a workaround until verify_peer is enabled by default.
    default(:verify_api_cert) { ChefConfig::Config.local_mode }

    # Path to the default CA bundle files.
    default :ssl_ca_path, nil
    default(:ssl_ca_file) do
      if ChefUtils.windows? && embedded_dir
        cacert_path = File.join(embedded_dir, "ssl/certs/cacert.pem")
        cacert_path if File.exist?(cacert_path)
      else
        nil
      end
    end

    # A directory that contains additional SSL certificates to trust. Any
    # certificates in this directory will be added to whatever CA bundle ruby
    # is using. Use this to add self-signed certs for your Chef Server or local
    # HTTP file servers.
    default(:trusted_certs_dir) { PathHelper.join(config_dir, "trusted_certs") }

    # A directory that contains additional configuration scripts to load for chef-client
    default(:client_d_dir) { PathHelper.join(config_dir, "client.d") }

    # A directory that contains additional configuration scripts to load for solo
    default(:solo_d_dir) { PathHelper.join(config_dir, "solo.d") }

    # A directory that contains additional configuration scripts to load for
    # the workstation config
    default(:config_d_dir) { PathHelper.join(config_dir, "config.d") }

    # Where should chef-solo download recipes from?
    default :recipe_url, nil

    # Set to true if Chef is to set OpenSSL to run in FIPS mode
    default(:fips) do
      # CHEF_FIPS is used in testing to override checking for system level
      # enablement. There are 3 possible values that this variable may have:
      # nil - no override and the system will be checked
      # empty - FIPS is NOT enabled
      # a non empty value - FIPS is enabled
      if ENV["CHEF_FIPS"] == ""
        false
      else
        !ENV["CHEF_FIPS"].nil? || ChefConfig.fips?
      end
    end

    # Initialize openssl
    def self.init_openssl
      if fips
        enable_fips_mode
      end
    end

    # Sets the version of the signed header authentication protocol to use (see
    # the 'mixlib-authorization' project for more detail). Currently, versions
    # 1.0, 1.1, and 1.3 are available.
    default :authentication_protocol_version do
      if fips || ssh_agent_signing
        "1.3"
      else
        "1.1"
      end
    end

    # This key will be used to sign requests to the Chef server. This location
    # must be writable by Chef during initial setup when generating a client
    # identity on the server.
    #
    # The chef-server will look up the public key for the client using the
    # `node_name` of the client.
    #
    # If chef-zero is enabled, this defaults to nil (no authentication).
    default(:client_key) do
      if chef_zero.enabled
        nil
      elsif target_mode?
        PathHelper.cleanpath("#{etc_chef_dir}/#{target_mode.host}/client.pem")
      else
        PathHelper.cleanpath("#{etc_chef_dir}/client.pem")
      end
    end

    # A credentials file may contain a complete client key, rather than the path
    # to one.
    #
    # We'll use this preferentially.
    default :client_key_contents, nil

    # When registering the client, should we allow the client key location to
    # be a symlink?  eg: /etc/chef/client.pem -> /etc/chef/prod-client.pem
    # If the path of the key goes through a directory like /tmp this should
    # never be set to true or its possibly an easily exploitable security hole.
    default :follow_client_key_symlink, false

    # Enable ssh-agent signing mode. This requires {client_key} be set to a
    # public key rather than the usual private key.
    default :ssh_agent_signing, false

    # This secret is used to decrypt encrypted data bag items.
    default(:encrypted_data_bag_secret) do
      if target_mode? && File.exist?(PathHelper.cleanpath("#{etc_chef_dir}/#{target_mode.host}/encrypted_data_bag_secret"))
        PathHelper.cleanpath("#{etc_chef_dir}/#{target_mode.host}/encrypted_data_bag_secret")
      elsif File.exist?(PathHelper.cleanpath("#{etc_chef_dir}/encrypted_data_bag_secret"))
        PathHelper.cleanpath("#{etc_chef_dir}/encrypted_data_bag_secret")
      else
        nil
      end
    end

    # As of Chef 13.0, version "3" is the default encrypted data bag item
    # format.
    #
    default :data_bag_encrypt_version, 3

    # When reading data bag items, any supported version is accepted. However,
    # if all encrypted data bags have been generated with the version 2 format,
    # it is recommended to disable support for earlier formats to improve
    # security. For example, the version 2 format is identical to version 1
    # except for the addition of an HMAC, so an attacker with MITM capability
    # could downgrade an encrypted data bag to version 1 as part of an attack.
    default :data_bag_decrypt_minimum_version, 0

    # If there is no file in the location given by `client_key`, chef-client
    # will temporarily use the "validator" identity to generate one. If the
    # `client_key` is not present and the `validation_key` is also not present,
    # chef-client will not be able to authenticate to the server.
    #
    # The `validation_key` is never used if the `client_key` exists.
    #
    # If chef-zero is enabled, this defaults to nil (no authentication).
    default(:validation_key) { chef_zero.enabled ? nil : PathHelper.cleanpath("#{etc_chef_dir}/validation.pem") }
    default :validation_client_name do
      # If the URL is set and looks like a normal Chef Server URL, extract the
      # org name and use that as part of the default.
      if chef_server_url.to_s =~ %r{/organizations/(.*)$}
        "#{$1}-validator"
      else
        "#{ChefUtils::Dist::Infra::SHORT}-validator"
      end
    end

    default :validation_key_contents, nil
    # When creating a new client via the validation_client account, Chef 11
    # servers allow the client to generate a key pair locally and send the
    # public key to the server. This is more secure and helps offload work from
    # the server, enhancing scalability. If enabled and the remote server
    # implements only the Chef 10 API, client registration will not work
    # properly.
    #
    # The default value is `true`. Set to `false` to disable client-side key
    # generation (server generates client keys).
    default(:local_key_generation) { true }

    # Zypper package provider gpg checks. Set to false to disable package
    # gpg signature checking globally.  This will warn you that it is a
    # bad thing to do.
    default :zypper_check_gpg, true

    # Report Handlers
    default :report_handlers, []

    # Event Handlers
    default :event_handlers, []

    default :disable_event_loggers, false

    # Exception Handlers
    default :exception_handlers, []

    # Start handlers
    default :start_handlers, []

    # Syntax Check Cache. Knife keeps track of files that is has already syntax
    # checked by storing files in this directory. `syntax_check_cache_path` is
    # the new (and preferred) configuration setting. If not set, knife will
    # fall back to using cache_options[:path], which is deprecated but exists in
    # many client configs generated by pre-Chef-11 bootstrappers.
    default(:syntax_check_cache_path) { cache_options[:path] }.writes_value { |path| expand_relative_paths(path) }

    # Deprecated:
    # Move this to the default value of syntax_cache_path when this is removed.
    default(:cache_options) { { path: PathHelper.join(config_dir, "syntaxcache") } }

    # Whether errors should be raised for deprecation warnings. When set to
    # `false` (the default setting), a warning is emitted but code using
    # deprecated methods/features/etc. should work normally otherwise. When set
    # to `true`, usage of deprecated methods/features will raise a
    # `DeprecatedFeatureError`. This is used by Chef's tests to ensure that
    # deprecated functionality is not used internally by Chef.  End users
    # should generally leave this at the default setting (especially in
    # production), but it may be useful when testing cookbooks or other code if
    # the user wishes to aggressively address deprecations.
    default(:treat_deprecation_warnings_as_errors) do
      # Using an environment variable allows this setting to be inherited in
      # tests that spawn new processes.
      ENV.key?("CHEF_TREAT_DEPRECATION_WARNINGS_AS_ERRORS")
    end

    # Which deprecations warnings to silence. Can be set to `true` to silence
    # all warnings, or an array of strings like either `"deprecation_type"` or
    # `"filename.rb:lineno"`.
    default :silence_deprecation_warnings, []

    # Whether the resource count should be updated for log resource
    # on running chef-client
    default :count_log_resource_updates, false

    # The selected profile when using credentials.
    default :profile, nil

    default :chef_guid_path do
      PathHelper.join(config_dir, "#{ChefUtils::Dist::Infra::SHORT}_guid")
    end

    default :chef_guid, nil

    # knife configuration data
    config_context :knife do
      default :hints, {}
    end

    def self.set_defaults_for_windows
      # Those lists of regular expressions define what chef considers a
      # valid user and group name
      # From http://technet.microsoft.com/en-us/library/cc776019(WS.10).aspx
      principal_valid_regex_part = '[^"\/\\\\\[\]\:;|=,+*?<>]+'
      default :user_valid_regex, [ /^(#{principal_valid_regex_part}\\)?#{principal_valid_regex_part}$/ ]
      default :group_valid_regex, [ /^(#{principal_valid_regex_part}\\)?#{principal_valid_regex_part}$/ ]

      default :fatal_windows_admin_check, false
    end

    def self.set_defaults_for_nix
      # Those lists of regular expressions define what chef considers a
      # valid user and group name
      #
      # user/group cannot start with '-', '+' or '~'
      # user/group cannot contain ':', ',' or non-space-whitespace or null byte
      # everything else is allowed (UTF-8, spaces, etc) and we delegate to your O/S useradd program to barf or not
      # copies: http://anonscm.debian.org/viewvc/pkg-shadow/debian/trunk/debian/patches/506_relaxed_usernames?view=markup
      default :user_valid_regex, [ /^[^-+~:,\t\r\n\f\0]+[^:,\t\r\n\f\0]*$/ ]
      default :group_valid_regex, [ /^[^-+~:,\t\r\n\f\0]+[^:,\t\r\n\f\0]*$/ ]
    end

    # Those lists of regular expressions define what chef considers a
    # valid user and group name
    if ChefUtils.windows?
      set_defaults_for_windows
    else
      set_defaults_for_nix
    end

    # This provides a hook which rspec can stub so that we can avoid twiddling
    # global state in tests.
    def self.env
      ENV
    end

    def self.windows_home_path
      ChefConfig.logger.deprecation("Chef::Config.windows_home_path is now deprecated.  Consider using Chef::Util::PathHelper.home instead.")
      PathHelper.home
    end

    # returns a platform specific path to the user home dir if set, otherwise default to current directory.
    default( :user_home ) { PathHelper.home || Dir.pwd }

    # Enable file permission fixup for selinux. Fixup will be done
    # only if selinux is enabled in the system.
    default :enable_selinux_file_permission_fixup, true

    # Use atomic updates (i.e. move operation) while updating contents
    # of the files resources. When set to false copy operation is
    # used to update files.
    #
    # NOTE: CHANGING THIS SETTING MAY CAUSE CORRUPTION, DATA LOSS AND
    # INSTABILITY.
    #
    default :file_atomic_update, true

    # There are 3 possible values for this configuration setting.
    # true => file staging is done in the destination directory
    # false => file staging is done via tempfiles under ENV['TMP']
    # :auto => file staging will try using destination directory if possible and
    #   will fall back to ENV['TMP'] if destination directory is not usable.
    #
    default :file_staging_uses_destdir, :auto

    # Exit if another run is in progress and the chef-client is unable to
    # get the lock before time expires. If nil, no timeout is enforced. (Exits
    # immediately if 0.)
    #
    default :run_lock_timeout, nil

    # Number of worker threads for syncing cookbooks in parallel. Increasing
    # this number can result in gateway errors from the server (namely 503 and 504).
    # If you are seeing this behavior while using the default setting, reducing
    # the number of threads will help.
    #
    default :cookbook_sync_threads, 10

    # True if all resources by default default to unified mode, with all resources
    # applying in "compile" mode, with no "converge" mode. False is backwards compatible
    # setting for Chef 11-15 behavior.  This will break forward notifications.
    #
    default :resource_unified_mode_default, false

    # At the beginning of the Chef Client run, the cookbook manifests are downloaded which
    # contain URLs for every file in every relevant cookbook.  Most of the files
    # (recipes, resources, providers, libraries, etc) are immediately synchronized
    # at the start of the run.  The handling of "files" and "templates" directories,
    # however, have two modes of operation.  They can either all be downloaded immediately
    # at the start of the run (no_lazy_load==true) or else they can be lazily loaded as
    # cookbook_file or template resources are converged which require them (no_lazy_load==false).
    #
    # The advantage of lazily loading these files is that unnecessary files are not
    # synchronized.  This may be useful to users with large files checked into cookbooks which
    # are only selectively downloaded to a subset of clients which use the cookbook.  However,
    # better solutions are to either isolate large files into individual cookbooks and only
    # include those cookbooks in the run lists of the servers that need them -- or move to
    # using remote_file and a more appropriate backing store like S3 for large file
    # distribution.
    #
    # The disadvantages of lazily loading files are that users some time find it
    # confusing that their cookbooks are not fully synchronized to the cache initially,
    # and more importantly the time-sensitive URLs which are in the manifest may time
    # out on long Chef runs before the resource that uses the file is converged
    # (leading to many confusing 403 errors on template/cookbook_file resources).
    #
    default :no_lazy_load, true

    # A array of attributes you want sent over the wire when node
    # data is saved. The default setting is nil, which collects all data.
    # NOTE: Setting to [] will not collect ANY data to save.
    default :allowed_automatic_attributes, nil
    default :allowed_default_attributes, nil
    default :allowed_normal_attributes, nil
    default :allowed_override_attributes, nil

    # An array of attributes you do not want to send over the
    # wire when node data is saved
    # The default setting is nil, which collects all data.
    # NOTE: Setting to [] will still collect all data to save
    default :blocked_automatic_attributes, nil
    default :blocked_default_attributes, nil
    default :blocked_normal_attributes, nil
    default :blocked_override_attributes, nil

    # deprecated config options that will be removed in Chef Infra Client 18
    default :automatic_attribute_blacklist, nil
    default :default_attribute_blacklist, nil
    default :normal_attribute_blacklist, nil
    default :override_attribute_blacklist, nil
    default :automatic_attribute_whitelist, nil
    default :default_attribute_whitelist, nil
    default :normal_attribute_whitelist, nil
    default :override_attribute_whitelist, nil

    # Pull down all the rubygems versions from rubygems and cache them the first time we do a gem_package or
    # chef_gem install.  This is memory-expensive and will grow without bounds, but will reduce network
    # round trips.
    default :rubygems_cache_enabled, false

    config_context :windows_service do
      # Set `watchdog_timeout` to the number of seconds to wait for a chef-client run
      # to finish
      default :watchdog_timeout, 2 * (60 * 60) # 2 hours
    end

    # Add an empty and non-strict config_context for chefdk and chefcli.
    # This lets the user have code like `chefdk.generator_cookbook "/path/to/cookbook"` or
    # `chefcli[:generator_cookbook] = "/path/to/cookbook"` in their config.rb,
    # and it will be ignored by tools like knife and ohai. ChefDK and ChefCLI
    # themselves can define the config options it accepts and enable strict mode,
    # and that will only apply when running `chef` commands.
    config_context :chefdk do
    end

    config_context :chefcli do
    end

    # Configuration options for Data Collector reporting. These settings allow
    # the user to configure where to send their Data Collector data, what token
    # to send, and whether Data Collector should report its findings in client
    # mode vs. solo mode.
    config_context :data_collector do
      # Full URL to the endpoint that will receive our data. If nil, the
      # data collector will not run.
      # Ex: http://my-data-collector.mycompany.com/ingest
      default(:server_url) do
        if config_parent.solo_legacy_mode || config_parent.local_mode
          nil
        else
          File.join(config_parent.chef_server_url, "/data-collector")
        end
      end

      # An optional pre-shared token to pass as an HTTP header (x-data-collector-token)
      # that can be used to determine whether or not the poster of this
      # run data should be trusted.
      # Ex: some-uuid-here
      default :token,            nil

      # The Chef mode during which Data Collector is allowed to function. This
      # can be used to run Data Collector only when running as Chef Solo but
      # not when using Chef Client.
      # Options: :solo (for both Solo Legacy Mode and Client Local Mode), :client, :both
      default :mode,             :both

      # When the Data Collector cannot send the "starting a run" message to
      # the Data Collector server, the Data Collector will be disabled for that
      # run. In some situations, such as highly-regulated environments, it
      # may be more reasonable to prevent Chef from performing the actual run.
      # In these situations, setting this value to true will cause the Chef
      # run to raise an exception before starting any converge activities.
      default :raise_on_failure, false

      # A user-supplied Organization string that can be sent in payloads
      # generated by the DataCollector when Chef is run in Solo mode. This
      # allows users to associate their Solo nodes with faux organizations
      # without the nodes being connected to an actual Chef Server.
      default :organization, "#{ChefUtils::Dist::Infra::SHORT}_solo"
    end

    configurable(:http_proxy)
    configurable(:http_proxy_user)
    configurable(:http_proxy_pass)
    configurable(:https_proxy)
    configurable(:https_proxy_user)
    configurable(:https_proxy_pass)
    configurable(:ftp_proxy)
    configurable(:ftp_proxy_user)
    configurable(:ftp_proxy_pass)
    configurable(:no_proxy)

    # Public method that users should call to export proxies to the appropriate
    # environment variables.  This method should be called after the config file is
    # parsed and loaded.
    # TODO add some post-file-parsing logic that automatically calls this so
    # users don't have to
    def self.export_proxies
      export_proxy("http", http_proxy, http_proxy_user, http_proxy_pass) if key?(:http_proxy) && http_proxy
      export_proxy("https", https_proxy, https_proxy_user, https_proxy_pass) if key?(:https_proxy) && https_proxy
      export_proxy("ftp", ftp_proxy, ftp_proxy_user, ftp_proxy_pass) if key?(:ftp_proxy) && ftp_proxy
      export_no_proxy(no_proxy) if key?(:no_proxy) && no_proxy
    end

    # Builds a proxy uri and exports it to the appropriate environment variables. Examples:
    #   http://username:password@hostname:port
    #   https://username@hostname:port
    #   ftp://hostname:port
    # when
    #   scheme = "http", "https", or "ftp"
    #   hostport = hostname:port or scheme://hostname:port
    #   user = username
    #   pass = password
    # @api private
    def self.export_proxy(scheme, path, user, pass)
      # Character classes for Addressable
      # See https://www.ietf.org/rfc/rfc3986.txt 3.2.1
      # The user part may not have a : in it
      user_class = Addressable::URI::CharacterClasses::UNRESERVED + Addressable::URI::CharacterClasses::SUB_DELIMS
      # The password part may have any valid USERINFO characters
      password_class = user_class + "\\:"

      path = "#{scheme}://#{path}" unless path.include?("://")
      # URI.split returns the following parts:
      # [scheme, userinfo, host, port, registry, path, opaque, query, fragment]
      uri = Addressable::URI.encode(path, Addressable::URI)

      if user && !user.empty?
        userinfo = Addressable::URI.encode_component(user, user_class)
        if pass
          userinfo << ":#{Addressable::URI.encode_component(pass, password_class)}"
        end
        uri.userinfo = userinfo
      end

      path = uri.to_s
      ENV["#{scheme}_proxy".downcase] = path unless ENV["#{scheme}_proxy".downcase]
      ENV["#{scheme}_proxy".upcase] = path unless ENV["#{scheme}_proxy".upcase]
    end

    # @api private
    def self.export_no_proxy(value)
      ENV["no_proxy"] = value unless ENV["no_proxy"]
      ENV["NO_PROXY"] = value unless ENV["NO_PROXY"]
    end

    # Given a scheme, host, and port, return the correct proxy URI based on the
    # set environment variables, unless excluded by no_proxy, in which case nil
    # is returned
    def self.proxy_uri(scheme, host, port)
      proxy_env_var = ENV["#{scheme}_proxy"].to_s.strip

      # Check if the proxy string contains a scheme. If not, add the url's scheme to the
      # proxy before parsing. The regex /^.*:\/\// matches, for example, http://. Reusing proxy
      # here since we are really just trying to get the string built correctly.
      proxy = unless proxy_env_var.empty?
                if %r{^.*://}.match?(proxy_env_var)
                  URI.parse(proxy_env_var)
                else
                  URI.parse("#{scheme}://#{proxy_env_var}")
                end
              end

      return proxy unless fuzzy_hostname_match_any?(host, ENV["no_proxy"])
    end

    # Chef requires an English-language UTF-8 locale to function properly.  We attempt
    # to use the 'locale -a' command and search through a list of preferences until we
    # find one that we can use.  On Ubuntu systems we should find 'C.UTF-8' and be
    # able to use that even if there is no English locale on the server, but Mac, Solaris,
    # AIX, etc do not have that locale.  We then try to find an English locale and fall
    # back to 'C' if we do not.  The choice of fallback is pick-your-poison.  If we try
    # to do the work to return a non-US UTF-8 locale then we fail inside of providers when
    # things like 'svn info' return Japanese and we can't parse them.  OTOH, if we pick 'C' then
    # we will blow up on UTF-8 characters.  Between the warn we throw and the Encoding
    # exception that ruby will throw it is more obvious what is broken if we drop UTF-8 by
    # default rather than drop English.
    #
    # If there is no 'locale -a' then we return 'en_US.UTF-8' since that is the most commonly
    # available English UTF-8 locale.  However, all modern POSIXen should support 'locale -a'.
    def self.guess_internal_locale
      # https://github.com/chef/chef/issues/2181
      # Some systems have the `locale -a` command, but the result has
      # invalid characters for the default encoding.
      #
      # For example, on CentOS 6 with ENV['LANG'] = "en_US.UTF-8",
      # `locale -a`.split fails with ArgumentError invalid UTF-8 encoding.
      cmd = Mixlib::ShellOut.new("locale -a").run_command
      cmd.error!
      locales = cmd.stdout.split
      case
      when locales.include?("C.UTF-8")
        "C.UTF-8"
      when locales.include?("en_US.UTF-8"), locales.include?("en_US.utf8")
        "en_US.UTF-8"
      when locales.include?("en.UTF-8")
        "en.UTF-8"
      else
        # Will match en_ZZ.UTF-8, en_ZZ.utf-8, en_ZZ.UTF8, en_ZZ.utf8
        guesses = locales.select { |l| l =~ /^en_.*UTF-?8$/i }
        unless guesses.empty?
          guessed_locale = guesses.first
          # Transform into the form en_ZZ.UTF-8
          guessed_locale.gsub(/UTF-?8$/i, "UTF-8")
        else
          ChefConfig.logger.warn "Please install an English UTF-8 locale for #{ChefUtils::Dist::Infra::PRODUCT} to use, falling back to C locale and disabling UTF-8 support."
          "C"
        end
      end
    rescue
      if ChefUtils.windows?
        ChefConfig.logger.trace "Defaulting to locale en_US.UTF-8 on Windows, until it matters that we do something else."
      else
        ChefConfig.logger.trace "No usable locale -a command found, assuming you have en_US.UTF-8 installed."
      end
      "en_US.UTF-8"
    end

    default :internal_locale, guess_internal_locale

    # Force UTF-8 Encoding, for when we fire up in the 'C' locale or other strange locales (e.g.
    # japanese windows encodings).  If we do not do this, then knife upload will fail when a cookbook's
    # README.md has UTF-8 characters that do not encode in whatever surrounding encoding we have been
    # passed.  Effectively, the Chef Ecosystem is globally UTF-8 by default.  Anyone who wants to be
    # able to upload Shift_JIS or ISO-8859-1 files needs to mark *those* files explicitly with
    # magic tags to make ruby correctly identify the encoding being used.  Changing this default will
    # break Chef community cookbooks and is very highly discouraged.
    default :ruby_encoding, Encoding::UTF_8

    # can be set to a string or array of strings for URIs to set as rubygems sources
    default :rubygems_url, nil

    # globally sets the default of the clear_sources property on the gem_package and chef_gem resources
    default :clear_gem_sources, nil

    # If installed via an omnibus installer, this gives the path to the
    # "embedded" directory which contains all of the software packaged with
    # omnibus. This is used to locate the cacert.pem file on windows.
    def self.embedded_dir
      Pathname.new(_this_file).ascend do |path|
        if path.basename.to_s == "embedded"
          return path.to_s
        end
      end

      nil
    end

    # Path to this file in the current install.
    def self._this_file
      File.expand_path(__FILE__)
    end

    # Set fips mode in openssl. Do any patching necessary to make
    # sure Chef runs do not crash.
    # @api private
    def self.enable_fips_mode
      OpenSSL.fips_mode = true
      require "digest" unless defined?(Digest)
      require "digest/sha1" unless defined?(Digest::SHA1)
      require "digest/md5" unless defined?(Digest::MD5)
      # Remove pre-existing constants if they do exist to reduce the
      # amount of log spam and warnings.
      Digest.send(:remove_const, "SHA1") if Digest.const_defined?("SHA1")
      Digest.const_set("SHA1", OpenSSL::Digest::SHA1)
      OpenSSL::Digest.send(:remove_const, "MD5") if OpenSSL::Digest.const_defined?("MD5")
      OpenSSL::Digest.const_set("MD5", Digest::MD5)
      ChefConfig.logger.debug "FIPS mode is enabled."
    end
  end
end
