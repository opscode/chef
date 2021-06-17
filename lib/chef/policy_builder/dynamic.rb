#
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

require "forwardable" unless defined?(Forwardable)

require_relative "../log"
require_relative "../run_context"
require_relative "../config"
require_relative "../node"
require_relative "../exceptions"
require_relative "expand_node_object"
require_relative "policyfile"

class Chef
  module PolicyBuilder

    # PolicyBuilder that selects either a Policyfile or non-Policyfile
    # implementation based on the content of the node object.
    class Dynamic

      extend Forwardable

      attr_reader :node
      attr_reader :node_name
      attr_reader :ohai_data
      attr_reader :json_attribs
      attr_reader :override_runlist
      attr_reader :events

      def initialize(node_name, ohai_data, json_attribs, override_runlist, events)
        @implementation = nil

        @node_name = node_name
        @ohai_data = ohai_data
        @json_attribs = json_attribs
        @override_runlist = override_runlist
        @events = events

        @node = nil
      end

      ## PolicyBuilder API ##

      # Loads the node state from the server, then picks the correct
      # implementation class based on the node and json_attribs.
      #
      # Calls #finish_load_node on the implementation object to complete the
      # loading process. All subsequent lifecycle calls are delegated.
      #
      # @return [Chef::Node] the loaded node.
      def load_node
        events.node_load_start(node_name, config)
        Chef::Log.trace("Building node object for #{node_name}")

        @node =
          if Chef::Config[:solo_legacy_mode]
            Chef::Node.build(node_name)
          else
            Chef::Node.find_or_create(node_name)
          end
        select_implementation(node)
        implementation.finish_load_node(node)
        node
        events.node_load_success(node)
      rescue Exception => e
        events.node_load_failed(node_name, e, config)
        raise
      end

      ## Delegated Public API Methods ##

      ### Accessors ###

      def_delegator :implementation, :original_runlist
      def_delegator :implementation, :run_context
      def_delegator :implementation, :run_list_expansion

      ### Lifecycle Methods ###

      # @!method build_node
      #
      # Applies external attributes (e.g., from JSON file, environment,
      # policyfile, etc.) and determines the correct expanded run list for the
      # run.
      #
      # @return [Chef::Node]
      def_delegator :implementation, :build_node

      # @!method setup_run_context
      #
      # Synchronizes cookbooks and initializes the run context object for the
      # run.
      #
      # @return [Chef::RunContext]
      def_delegator :implementation, :setup_run_context

      # @!method expanded_run_list
      #
      # Resolves the run list to a form containing only recipes and sets the
      # `roles` and `recipes` automatic attributes on the node.
      #
      # @return [#recipes, #roles] A RunListExpansion or duck-type.
      def_delegator :implementation, :expand_run_list

      # @!method sync_cookbooks
      #
      # Synchronizes cookbooks. In a normal chef-client run, this is handled by
      # #setup_run_context, but may be called directly in some circumstances.
      #
      # @return [Hash{String => Chef::CookbookManifest}] A map of
      #   CookbookManifest objects by cookbook name.
      def_delegator :implementation, :sync_cookbooks

      # @!method temporary_policy?
      #
      # Indicates whether the policy is temporary, which means an
      # override_runlist was provided. Chef::Client uses this to decide whether
      # to do the final node save at the end of the run or not.
      #
      # @return [true,false]
      def_delegator :implementation, :temporary_policy?

      ## Internal Public API ##

      # Returns the selected implementation, or raises if not set. The
      # implementation is set when #load_node is called.
      #
      # @return [PolicyBuilder::Policyfile, PolicyBuilder::ExpandNodeObject]
      def implementation
        @implementation || raise(Exceptions::InvalidPolicybuilderCall, "#load_node must be called before other policy builder methods")
      end

      # @api private
      #
      # Sets the implementation based on the content of the node, node JSON
      # (i.e., the `-j JSON_FILE` data), and config. This is only public for
      # testing purposes; production code should call #load_node instead.
      def select_implementation(node)
        if policyfile_set_in_config? ||
            policyfile_attribs_in_node_json? ||
            node_has_policyfile_attrs?(node)
          @implementation = Policyfile.new(node_name, ohai_data, json_attribs, override_runlist, events)
        else
          @implementation = ExpandNodeObject.new(node_name, ohai_data, json_attribs, override_runlist, events)
        end
      end

      def config
        Chef::Config
      end

      private

      def node_has_policyfile_attrs?(node)
        node.policy_name || node.policy_group
      end

      def policyfile_attribs_in_node_json?
        json_attribs.key?("policy_name") || json_attribs.key?("policy_group")
      end

      def policyfile_set_in_config?
        config[:policy_name] || config[:policy_group]
      end
    end
  end
end
