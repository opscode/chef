#
# Author:: Adam Jacob (<adam@chef.io>)
# Author:: Tim Hinderliter (<tim@chef.io>)
# Author:: Christopher Walters (<cw@chef.io>)
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

require_relative "../log"
require_relative "../run_context"
require_relative "../config"
require_relative "../node"
require_relative "../server_api"
require "chef-utils/dist" unless defined?(ChefUtils::Dist)

class Chef
  module PolicyBuilder

    # Policyfile is a policy builder implementation that gets run
    # list and cookbook version information from a single document.
    #
    # Does not support legacy chef-solo or roles/environments.
    #
    class Policyfile

      class UnsupportedFeature < StandardError; end

      class PolicyfileError < StandardError; end

      RunListExpansionIsh = Struct.new(:recipes, :roles) do
        # Implementing the parts of the RunListExpansion
        # interface we need to properly send this through to
        # events.run_list_expanded as it is expecting a RunListExpansion
        # object.
        def to_h
          # It looks like version only gets populated in the expanded_run_list when
          # using a little used feature of roles to version lock cookbooks, so
          # version is not reliable in here anyway (places like Automate UI are
          # not getting version out of here.
          #
          # Skipped will always be false as it can only be true when two expanded
          # roles contain the same recipe.
          expanded_run_list = recipes.map do |r|
            { type: "recipe", name: r, skipped: false, version: nil }
          end
          data_collector_hash = {}
          data_collector_hash[:id] = "_policy_node"
          data_collector_hash[:run_list] = expanded_run_list
          data_collector_hash
        end

        alias_method :to_hash, :to_h

        def to_json(*opts)
          to_h.to_json(*opts)
        end
      end

      attr_reader :events
      attr_reader :node
      attr_reader :node_name
      attr_reader :ohai_data
      attr_reader :json_attribs
      attr_reader :run_context
      attr_reader :override_runlist

      def initialize(node_name, ohai_data, json_attribs, override_runlist, events)
        @node_name = node_name
        @ohai_data = ohai_data
        @override_runlist = override_runlist
        @json_attribs = json_attribs
        @events = events

        @node = nil

        if Chef::Config[:solo_legacy_mode]
          raise UnsupportedFeature, "Policyfile does not support chef-solo. Use #{ChefUtils::Dist::Infra::CLIENT} local mode instead."
        end

        if Chef::Config[:environment] && !Chef::Config[:environment].chomp.empty?
          raise UnsupportedFeature, "Policyfile does not work with an Environment configured."
        end
      end

      # Policyfile gives you the run_list already expanded, but users of this
      # class may expect to get a run_list expansion compatible object by
      # calling this method.
      #
      # === Returns
      # RunListExpansionIsh:: A RunListExpansion duck type
      def run_list_expansion
        run_list_expansion_ish
      end

      ## PolicyBuilder API ##

      def finish_load_node(node)
        @node = node
        select_policy_name_and_group
        validate_policyfile
        events.policyfile_loaded(policy)
      end

      # Applies environment, external JSON attributes, and override run list to
      # the node, Then expands the run_list.
      #
      # === Returns
      # node<Chef::Node>:: The modified node object. node is modified in place.
      def build_node
        # consume_external_attrs may add items to the run_list. Save the
        # expanded run_list, which we will pass to the server later to
        # determine which versions of cookbooks to use.

        unless Chef::Config[:policy_document_native_api]
          Chef.deprecated(:policyfile_compat_mode, "The chef-server 11 policyfile compat mode is deprecated, please set policy_document_native_api to true in your config")
        end

        node.reset_defaults_and_overrides

        node.consume_external_attrs(ohai_data, json_attribs)

        setup_run_list_override

        expand_run_list
        apply_policyfile_attributes

        if persistent_run_list_set?
          Chef::Log.warn("The node.run_list setting is overriding the Policyfile run_list")
        end
        Chef::Log.info("Run List is [#{run_list}]")
        Chef::Log.info("Run List expands to [#{run_list_with_versions_for_display(run_list).join(", ")}]")

        events.node_load_completed(node, run_list_with_versions_for_display(run_list), Chef::Config)
        events.run_list_expanded(run_list_expansion_ish)

        # we must do this after `node.consume_external_attrs`
        node.automatic_attrs[:policy_name] = node.policy_name
        node.automatic_attrs[:policy_group] = node.policy_group
        node.automatic_attrs[:chef_environment] = node.policy_group

        node
      rescue Exception => e
        events.node_load_failed(node_name, e, Chef::Config)
        raise
      end

      # Synchronizes cookbooks and initializes the run context object for the
      # run.
      #
      # @return [Chef::RunContext]
      def setup_run_context(specific_recipes = nil, run_context = nil)
        run_context ||= Chef::RunContext.new
        run_context.node = node
        run_context.events = events

        Chef::Cookbook::FileVendor.fetch_from_remote(api_service)
        sync_cookbooks
        cookbook_collection = Chef::CookbookCollection.new(cookbooks_to_sync)
        cookbook_collection.validate!
        cookbook_collection.install_gems(events)

        run_context.cookbook_collection = cookbook_collection

        setup_chef_class(run_context)

        events.cookbook_compilation_start(run_context)

        run_context.load(run_list_expansion_ish)
        if specific_recipes
          specific_recipes.each do |recipe_file|
            run_context.load_recipe_file(recipe_file)
          end
        end

        events.cookbook_compilation_complete(run_context)

        setup_chef_class(run_context)
        run_context
      end

      # Sets `run_list` on the node from the policy, sets `roles` and `recipes`
      # attributes on the node accordingly.
      #
      # @return [RunListExpansionIsh] A RunListExpansion duck-type.
      def expand_run_list
        validate_run_list!(run_list)

        node.run_list(run_list)
        node.automatic_attrs[:policy_revision] = revision_id
        node.automatic_attrs[:roles] = []
        node.automatic_attrs[:recipes] = run_list_expansion_ish.recipes
        run_list_expansion_ish
      end

      # Synchronizes cookbooks. In a normal chef-client run, this is handled by
      # #setup_run_context, but may be called directly in some circumstances.
      #
      # @return [Hash{String => Chef::CookbookManifest}] A map of
      #   CookbookManifest objects by cookbook name.
      def sync_cookbooks
        Chef::Log.trace("Synchronizing cookbooks")
        synchronizer = Chef::CookbookSynchronizer.new(cookbooks_to_sync, events)
        synchronizer.sync_cookbooks

        # register the file cache path in the cookbook path so that CookbookLoader actually picks up the synced cookbooks
        Chef::Config[:cookbook_path] = File.join(Chef::Config[:file_cache_path], "cookbooks")

        cookbooks_to_sync
      end

      ## Internal Public API ##

      # @api private
      #
      # Validate run_list against policyfile cookbooks
      #
      def validate_run_list!(run_list)
        run_list.map do |recipe_spec|
          cookbook, recipe = parse_recipe_spec(recipe_spec)
          lock_data = cookbook_lock_for(cookbook)
          raise PolicyfileError, "invalid run_list item '#{recipe_spec}' not in cookbook set of PolicyFile #{policyfile_location}" unless lock_data
        end
      end

      # @api private
      #
      # Generates an array of strings with recipe names including version and
      # identifier info.
      def run_list_with_versions_for_display(run_list)
        run_list.map do |recipe_spec|
          cookbook, recipe = parse_recipe_spec(recipe_spec)
          lock_data = cookbook_lock_for(cookbook)
          display = "#{cookbook}::#{recipe}@#{lock_data["version"]} (#{lock_data["identifier"][0...7]})"
          display
        end
      end

      # @api private
      #
      # Sets up a RunListExpansionIsh object so that it can be used in place of
      # a RunListExpansion object, to satisfy the API contract of
      # #expand_run_list
      def run_list_expansion_ish
        recipes = run_list.map do |recipe_spec|
          cookbook, recipe = parse_recipe_spec(recipe_spec)
          "#{cookbook}::#{recipe}"
        end
        RunListExpansionIsh.new(recipes, [])
      end

      # @api private
      #
      # Sets attributes from the policyfile on the node, using the role priority.
      def apply_policyfile_attributes
        node.attributes.role_default = policy["default_attributes"]
        node.attributes.role_override = policy["override_attributes"]
        hoist_policyfile_attributes(node.policy_group) if node.policy_group
      end

      # @api private
      #
      # Hoists attributes from role_X[policy_group] up to the equivalent role_X level
      def hoist_policyfile_attributes(policy_group)
        Chef::Log.trace("Running attribute Hoist for group #{policy_group}")
        Chef::Mixin::DeepMerge.hash_only_merge!(node.role_default, node.role_default[policy_group]) if node.role_default.include?(policy_group)
        Chef::Mixin::DeepMerge.hash_only_merge!(node.role_override, node.role_override[policy_group]) if node.role_override.include?(policy_group)
      end

      # @api private
      def parse_recipe_spec(recipe_spec)
        rmatch = recipe_spec.to_s.match(/recipe\[([^:]+)::([^:]+)\]/)
        if rmatch.nil?
          rmatch = recipe_spec.to_s.match(/recipe\[([^:]+)\]/)
          if rmatch.nil?
            raise PolicyfileError, "invalid recipe specification #{recipe_spec} in Policyfile from #{policyfile_location}"
          else
            [rmatch[1], "default"]
          end
        else
          [rmatch[1], rmatch[2]]
        end
      end

      # @api private
      def cookbook_lock_for(cookbook_name)
        cookbook_locks[cookbook_name]
      end

      # @api private
      # @return [Array<String>]
      def run_list
        return override_runlist.map(&:to_s) if override_runlist

        if json_attribs["run_list"]
          json_attribs["run_list"]
        elsif persistent_run_list_set?
          node.run_list
        elsif named_run_list_requested?
          named_run_list || raise(ConfigurationError,
            "Policy '#{retrieved_policy_name}' revision '#{revision_id}' does not have named_run_list '#{named_run_list_name}'" +
            "(available named_run_lists: [#{available_named_run_lists.join(", ")}])")
        else
          policy["run_list"]
        end
      end

      # @api private
      def policy
        @policy ||= api_service.get(policyfile_location)
      rescue Net::HTTPClientException => e
        raise ConfigurationError, "Error loading policyfile from `#{policyfile_location}': #{e.class} - #{e.message}"
      end

      # @api private
      def policyfile_location
        if Chef::Config[:policy_document_native_api]
          validate_policy_config!
          "policy_groups/#{policy_group}/policies/#{policy_name}"
        else
          "data/policyfiles/#{deployment_group}"
        end
      end

      # Do some minimal validation of the policyfile we fetched from the
      # server. Compatibility mode relies on using data bags to store policy
      # files; therefore no real validation will be performed server-side and
      # we need to make additional checks to ensure the data will be formatted
      # correctly.
      def validate_policyfile
        errors = []
        unless run_list
          errors << "Policyfile is missing run_list element"
        end
        unless policy.key?("cookbook_locks")
          errors << "Policyfile is missing cookbook_locks element"
        end
        if run_list.is_a?(Array)
          run_list_errors = run_list.select do |maybe_recipe_spec|
            validate_recipe_spec(maybe_recipe_spec)
          end
          errors += run_list_errors
        else
          errors << "Policyfile run_list is malformed, must be an array of `recipe[cb_name::recipe_name]` items: #{policy["run_list"]}"
        end

        unless errors.empty?
          raise PolicyfileError, "Policyfile fetched from #{policyfile_location} was invalid:\n#{errors.join("\n")}"
        end
      end

      # @api private
      def validate_recipe_spec(recipe_spec)
        parse_recipe_spec(recipe_spec)
        nil
      rescue PolicyfileError => e
        e.message
      end

      class ConfigurationError < StandardError; end

      # @api private
      def deployment_group
        Chef::Config[:deployment_group] || raise(ConfigurationError, "Setting `deployment_group` is not configured.")
      end

      # @api private
      def validate_policy_config!
        raise ConfigurationError, "Setting `policy_group` is not configured." unless policy_group

        raise ConfigurationError, "Setting `policy_name` is not configured." unless policy_name
      end

      # @api private
      def policy_group
        Chef::Config[:policy_group]
      end

      # @api private
      def policy_name
        Chef::Config[:policy_name]
      end

      # @api private
      #
      # Selects the `policy_name` and `policy_group` from the following sources
      # in priority order:
      #
      # 1. JSON attribs (i.e., `-j JSON_FILE`)
      # 2. `Chef::Config`
      # 3. The node object
      #
      # The selected values are then copied to `Chef::Config` and the node.
      def select_policy_name_and_group
        policy_name_to_set =
          policy_name_from_json_attribs ||
          policy_name_from_config ||
          policy_name_from_node

        policy_group_to_set =
          policy_group_from_json_attribs ||
          policy_group_from_config ||
          policy_group_from_node

        node.policy_name = policy_name_to_set
        node.policy_group = policy_group_to_set
        node.chef_environment = policy_group_to_set

        Chef::Config[:policy_name] = policy_name_to_set
        Chef::Config[:policy_group] = policy_group_to_set
      end

      # @api private
      def policy_group_from_json_attribs
        json_attribs["policy_group"]
      end

      # @api private
      def policy_name_from_json_attribs
        json_attribs["policy_name"]
      end

      # @api private
      def policy_group_from_config
        Chef::Config[:policy_group]
      end

      # @api private
      def policy_name_from_config
        Chef::Config[:policy_name]
      end

      # @api private
      def policy_group_from_node
        node.policy_group
      end

      # @api private
      def policy_name_from_node
        node.policy_name
      end

      # @api private
      # Builds a 'cookbook_hash' map of the form
      #   "COOKBOOK_NAME" => "IDENTIFIER"
      #
      # This can be passed to a Chef::CookbookSynchronizer object to
      # synchronize the cookbooks.
      #
      # TODO: Currently this makes N API calls to the server to get the
      # cookbook objects. With server support (bulk API or the like), this
      # should be reduced to a single call.
      def cookbooks_to_sync
        @cookbook_to_sync ||= begin
          events.cookbook_resolution_start(run_list_with_versions_for_display(run_list))

          cookbook_versions_by_name = cookbook_locks.inject({}) do |cb_map, (name, lock_data)|
            cb_map[name] = manifest_for(name, lock_data)
            cb_map
          end
          events.cookbook_resolution_complete(cookbook_versions_by_name)

          cookbook_versions_by_name
        end
      rescue Exception => e
        # TODO: wrap/munge exception to provide helpful error output
        events.cookbook_resolution_failed(run_list_with_versions_for_display(run_list), e)
        raise
      end

      # @api private
      # Fetches the CookbookVersion object for the given name and identifier
      # specified in the lock_data.
      # TODO: This only implements Chef 11 compatibility mode, which means that
      # cookbooks are fetched by the "dotted_decimal_identifier": a
      # representation of a SHA1 in the traditional x.y.z version format.
      def manifest_for(cookbook_name, lock_data)
        if Chef::Config[:policy_document_native_api]
          artifact_manifest_for(cookbook_name, lock_data)
        else
          compat_mode_manifest_for(cookbook_name, lock_data)
        end
      end

      # @api private
      def cookbook_locks
        policy["cookbook_locks"]
      end

      # @api private
      def revision_id
        policy["revision_id"]
      end

      # @api private
      def api_service
        @api_service ||= Chef::ServerAPI.new(config[:chef_server_url],
          { version_class: Chef::CookbookManifestVersions })
      end

      # @api private
      def config
        Chef::Config
      end

      # Indicates whether the policy is temporary, which means an
      # override_runlist was provided. Chef::Client uses this to decide whether
      # to do the final node save at the end of the run or not.
      def temporary_policy?
        node.override_runlist_set?
      end

      private

      # This method injects the run_context and into the Chef class.
      #
      # NOTE: This is duplicated with the ExpandNodeObject implementation. If
      # it gets any more complicated, it needs to be moved elsewhere.
      #
      # @param run_context [Chef::RunContext] the run_context to inject
      def setup_chef_class(run_context)
        Chef.set_run_context(run_context)
      end

      def retrieved_policy_name
        policy["name"]
      end

      def named_run_list
        policy["named_run_lists"] && policy["named_run_lists"][named_run_list_name]
      end

      def available_named_run_lists
        (policy["named_run_lists"] || {}).keys
      end

      def persistent_run_list_set?
        Chef::Config[:policy_persist_run_list] && node.run_list && !node.run_list.empty?
      end

      def named_run_list_requested?
        !!Chef::Config[:named_run_list]
      end

      def named_run_list_name
        Chef::Config[:named_run_list]
      end

      def compat_mode_manifest_for(cookbook_name, lock_data)
        xyz_version = lock_data["dotted_decimal_identifier"]
        rel_url = "cookbooks/#{cookbook_name}/#{xyz_version}"
        inflate_cbv_object(api_service.get(rel_url))
      rescue Exception => e
        message = "Error loading cookbook #{cookbook_name} at version #{xyz_version} from #{rel_url}: #{e.class} - #{e.message}"
        err = Chef::Exceptions::CookbookNotFound.new(message)
        err.set_backtrace(e.backtrace)
        raise err
      end

      def artifact_manifest_for(cookbook_name, lock_data)
        identifier = lock_data["identifier"]
        rel_url = "cookbook_artifacts/#{cookbook_name}/#{identifier}"
        inflate_cbv_object(api_service.get(rel_url))
      rescue Exception => e
        message = "Error loading cookbook #{cookbook_name} with identifier #{identifier} from #{rel_url}: #{e.class} - #{e.message}"
        err = Chef::Exceptions::CookbookNotFound.new(message)
        err.set_backtrace(e.backtrace)
        raise err
      end

      def inflate_cbv_object(raw_manifest)
        Chef::CookbookVersion.from_cb_artifact_data(raw_manifest)
      end

      def setup_run_list_override
        unless override_runlist.nil?
          runlist_override_sanity_check!
          node.override_runlist = override_runlist
          Chef::Log.warn "Run List override has been provided."
          Chef::Log.warn "Original Run List: [#{node.primary_runlist}]"
          Chef::Log.warn "Overridden Run List: [#{node.run_list}]"
        end
      end

      # Ensures runlist override contains RunListItem instances
      def runlist_override_sanity_check!
        # Convert to array and remove whitespace
        if override_runlist.is_a?(String)
          @override_runlist = override_runlist.split(",").map(&:strip)
        end
        @override_runlist = [override_runlist].flatten.compact
        override_runlist.map! do |item|
          if item.is_a?(Chef::RunList::RunListItem)
            item
          else
            Chef::RunList::RunListItem.new(item)
          end
        end
      end

    end
  end
end
