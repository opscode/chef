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

require "spec_helper"
require "chef/policy_builder"

describe Chef::PolicyBuilder::Dynamic do

  let(:node_name) { "joe_node" }
  let(:ohai_data) { { "platform" => "ubuntu", "platform_version" => "13.04", "fqdn" => "joenode.example.com" } }
  let(:json_attribs) { { "custom_attr" => "custom_attr_value" } }
  let(:override_runlist) { nil }
  let(:events) { Chef::EventDispatch::Dispatcher.new }

  let(:err_namespace) { Chef::PolicyBuilder::Policyfile }

  let(:base_node) do
    node = Chef::Node.new
    node.name(node_name)
    node
  end

  let(:node) { base_node }

  subject(:policy_builder) { Chef::PolicyBuilder::Dynamic.new(node_name, ohai_data, json_attribs, override_runlist, events) }

  describe "loading policy data" do

    describe "delegating PolicyBuilder API to the correct implementation" do

      let(:implementation) { instance_double("Chef::PolicyBuilder::Policyfile") }

      before do
        allow(policy_builder).to receive(:implementation).and_return(implementation)
      end

      # Dynamic should load_node, figure out the correct backend, then forward
      # messages to it after. That behavior is tested below.
      it "responds to #load_node" do
        expect(policy_builder).to respond_to(:load_node)
      end

      it "forwards #original_runlist" do
        expect(implementation).to receive(:original_runlist)
        policy_builder.original_runlist
      end

      it "forwards #run_context" do
        expect(implementation).to receive(:run_context)
        policy_builder.run_context
      end

      it "forwards #run_list_expansion" do
        expect(implementation).to receive(:run_list_expansion)
        policy_builder.run_list_expansion
      end

      it "forwards #build_node to the implementation object" do
        expect(implementation).to receive(:build_node)
        policy_builder.build_node
      end

      it "forwards #setup_run_context to the implementation object" do
        expect(implementation).to receive(:setup_run_context)
        policy_builder.setup_run_context

        arg = Object.new

        expect(implementation).to receive(:setup_run_context).with(arg)
        policy_builder.setup_run_context(arg)
      end

      it "forwards #expand_run_list to the implementation object" do
        expect(implementation).to receive(:expand_run_list)
        policy_builder.expand_run_list
      end

      it "forwards #sync_cookbooks to the implementation object" do
        expect(implementation).to receive(:sync_cookbooks)
        policy_builder.sync_cookbooks
      end

      it "forwards #temporary_policy? to the implementation object" do
        expect(implementation).to receive(:temporary_policy?)
        policy_builder.temporary_policy?
      end

    end

    describe "selecting a backend implementation" do

      let(:implementation) do
        policy_builder.select_implementation(node)
        policy_builder.implementation
      end

      context "when no policyfile attributes are present on the node" do

        context "and json_attribs are not given" do

          let(:json_attribs) { {} }

          it "uses the ExpandNodeObject implementation" do
            expect(implementation).to be_a(Chef::PolicyBuilder::ExpandNodeObject)
          end

        end

        context "and no policyfile attributes are present in json_attribs" do

          let(:json_attribs) { { "foo" => "bar" } }

          it "uses the ExpandNodeObject implementation" do
            expect(implementation).to be_a(Chef::PolicyBuilder::ExpandNodeObject)
          end

        end

        context "and policy_name and policy_group are set on Chef::Config" do

          before do
            Chef::Config[:policy_name] = "example-policy"
            Chef::Config[:policy_group] = "testing"
          end

          it "uses the Policyfile implementation" do
            expect(implementation).to be_a(Chef::PolicyBuilder::Policyfile)
          end

        end

        context "and policyfile attributes are present in json_attribs" do

          let(:json_attribs) { { "policy_name" => "example-policy", "policy_group" => "testing" } }

          it "uses the Policyfile implementation" do
            expect(implementation).to be_a(Chef::PolicyBuilder::Policyfile)
          end

        end

      end

      context "when policyfile attributes are present on the node" do

        let(:node) do
          base_node.policy_name = "example-policy"
          base_node.policy_group = "staging"
          base_node
        end

        it "uses the Policyfile implementation" do
          expect(implementation).to be_a(Chef::PolicyBuilder::Policyfile)
        end

      end

    end

    describe "loading a node" do

      let(:implementation) { instance_double("Chef::PolicyBuilder::Policyfile") }

      before do
        allow(policy_builder).to receive(:implementation).and_return(implementation)
      end

      context "when not running chef solo" do

        context "when successful" do

          before do
            expect(Chef::Node).to receive(:find_or_create).with(node_name).and_return(node)
            expect(policy_builder).to receive(:select_implementation).with(node)
            expect(implementation).to receive(:finish_load_node).with(node)
          end

          it "selects the backend implementation and continues node loading" do
            policy_builder.load_node
          end

        end

        context "when an error occurs finding the node" do

          before do
            expect(Chef::Node).to receive(:find_or_create).with(node_name).and_raise("oops")
          end

          it "sends a node_load_failed event and re-raises" do
            expect(events).to receive(:node_load_failed)
            expect { policy_builder.load_node }.to raise_error("oops")
          end

        end

        context "when an error occurs in the implementation's finish_load_node call" do

          before do
            expect(Chef::Node).to receive(:find_or_create).with(node_name).and_return(node)
            expect(policy_builder).to receive(:select_implementation).with(node)
            expect(implementation).to receive(:finish_load_node).and_raise("oops")
          end

          it "sends a node_load_failed event and re-raises" do
            expect(events).to receive(:node_load_failed)
            expect { policy_builder.load_node }.to raise_error("oops")
          end

        end

      end

      context "when running chef solo" do

        before do
          Chef::Config[:solo_legacy_mode] = true
          expect(Chef::Node).to receive(:build).with(node_name).and_return(node)
          expect(policy_builder).to receive(:select_implementation).with(node)
          expect(implementation).to receive(:finish_load_node).with(node)
        end

        it "selects the backend implementation and continues node loading" do
          policy_builder.load_node
        end

      end

    end

  end

end
