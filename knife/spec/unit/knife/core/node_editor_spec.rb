#
# Author:: Jordan Running (<jr@chef.io>)
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

require "knife_spec_helper"
require "chef/knife/core/node_editor"

describe Chef::Knife::NodeEditor do
  let(:node_data) do
    { "name" => "test_node",
      "chef_environment" => "production",
      "automatic" => { "foo" => "bar" },
      "default" => { "alpha" => { "bravo" => "charlie", "delta" => "echo" } },
      "normal" => { "alpha" => { "bravo" => "hotel" }, "tags" => [] },
      "override" => { "alpha" => { "bravo" => "foxtrot", "delta" => "golf" } },
      "policy_name" => nil,
      "policy_group" => nil,
      "run_list" => %w{role[comedy] role[drama] recipe[mystery]},
    }
  end

  let(:node) { Chef::Node.from_hash(node_data) }

  let(:ui) { double "ui" }
  let(:base_config) { { editor: "cat" } }
  let(:config) { base_config.merge(all_attributes: false) }

  subject { described_class.new(node, ui, config) }

  describe "#view" do
    it "returns a Hash with only the name, chef_environment, normal, " +
      "policy_name, policy_group, and run_list properties" do
        expected = node_data.select do |key,|
          %w{ name chef_environment normal
              policy_name policy_group run_list }.include?(key)
        end

        expect(subject.view).to eq(expected)
      end

    context "when config[:all_attributes] == true" do
      let(:config) { base_config.merge(all_attributes: true) }

      it "returns a Hash with all of the node's properties" do
        expect(subject.view).to eq(node_data)
      end
    end
  end

  describe "#apply_updates" do
    context "when the node name is changed" do
      before(:each) do
        allow(ui).to receive(:warn)
        allow(ui).to receive(:confirm).and_return(true)
      end

      it "emits a warning and prompts for confirmation" do
        data = subject.view.merge("name" => "foo_new_name_node")
        updated_node = subject.apply_updates(data)

        expect(ui).to have_received(:warn)
          .with "Changing the name of a node results in a new node being " +
            "created, test_node will not be modified or removed."

        expect(ui).to have_received(:confirm)
          .with("Proceed with creation of new node")

        expect(updated_node).to be_a(Chef::Node)
      end
    end

    context "when config[:all_attributes] == false" do
      let(:config) { base_config.merge(all_attributes: false) }

      let(:updated_data) do
        subject.view.merge(
          "normal" => { "alpha" => { "bravo" => "hotel2" }, "tags" => [ "xyz" ] },
          "policy_name" => "mypolicy",
          "policy_group" => "prod",
          "run_list" => %w{role[drama] recipe[mystery]}
        )
      end

      it "returns a node with run_list and normal_attrs changed" do
        updated_node = subject.apply_updates(updated_data)
        expect(updated_node).to be_a(Chef::Node)

        # Expected to have been changed
        expect(updated_node.normal_attrs).to eql(updated_data["normal"])
        expect(updated_node.policy_name).to eql(updated_data["policy_name"])
        expect(updated_node.policy_group).to eql(updated_data["policy_group"])
        expect(updated_node.chef_environment).to eql(updated_data["policy_group"])
        expect(updated_node.run_list.map(&:to_s)).to eql(updated_data["run_list"])

        # Expected not to have changed
        expect(updated_node.default_attrs).to eql(node.default_attrs)
        expect(updated_node.override_attrs).to eql(node.override_attrs)
        expect(updated_node.automatic_attrs).to eql(node.automatic_attrs)
      end
    end

    context "when config[:all_attributes] == true" do
      let(:config) { base_config.merge(all_attributes: true) }

      let(:updated_data) do
        subject.view.merge(
          "default"   => { "alpha" => { "bravo" => "charlie2", "delta" => "echo2" } },
          "normal"    => { "alpha" => { "bravo" => "hotel2" }, "tags" => [ "xyz" ] },
          "override"  => { "alpha" => { "bravo" => "foxtrot2", "delta" => "golf2" } },
          "policy_name" => "mypolicy",
          "policy_group" => "prod",
          "run_list" => %w{role[drama] recipe[mystery]}
        )
      end

      it "returns a node with all editable properties changed" do
        updated_node = subject.apply_updates(updated_data)
        expect(updated_node).to be_a(Chef::Node)

        expect(updated_node.chef_environment).to eql(updated_data["policy_group"])
        expect(updated_node.automatic_attrs).to eql(updated_data["automatic"])
        expect(updated_node.normal_attrs).to eql(updated_data["normal"])
        expect(updated_node.default_attrs).to eql(updated_data["default"])
        expect(updated_node.override_attrs).to eql(updated_data["override"])
        expect(updated_node.policy_name).to eql(updated_data["policy_name"])
        expect(updated_node.policy_group).to eql(updated_data["policy_group"])
        expect(updated_node.run_list.map(&:to_s)).to eql(updated_data["run_list"])
      end
    end
  end

  describe "#updated?" do
    context "before the node has been edited" do
      it "returns false" do
        expect(subject.updated?).to be false
      end
    end

    context "after the node has been edited" do
      context "and changes were made" do
        let(:updated_data) do
          subject.view.merge(
            "default"   => { "alpha" => { "bravo" => "charlie2", "delta" => "echo2" } },
            "normal"    => { "alpha" => { "bravo" => "hotel2" }, "tags" => [ "xyz" ] },
            "override"  => { "alpha" => { "bravo" => "foxtrot2", "delta" => "golf2" } },
            "policy_name"  => "mypolicy",
            "policy_group" => "prod",
            "run_list" => %w{role[drama] recipe[mystery]}
          )
        end

        context "and changes affect only editable properties" do
          before(:each) do
            allow(ui).to receive(:edit_hash)
              .with(subject.view)
              .and_return(updated_data)

            subject.edit_node
          end

          it "returns an array of the changed property names" do
            expect(subject.updated?).to eql %w{ chef_environment normal policy_name policy_group run_list }
          end
        end

        context "and the changes include non-editable properties" do
          before(:each) do
            data = updated_data.merge("bad_property" => "bad_value")

            allow(ui).to receive(:edit_hash)
              .with(subject.view)
              .and_return(data)

            subject.edit_node
          end

          it "returns an array of property names that doesn't include " +
            "the non-editable properties" do
              expect(subject.updated?).to eql %w{ chef_environment normal policy_name policy_group run_list }
            end
        end
      end

      context "and changes were not made" do
        before(:each) do
          allow(ui).to receive(:edit_hash)
            .with(subject.view)
            .and_return(subject.view.dup)

          subject.edit_node
        end

        it { is_expected.not_to be_updated }
      end
    end
  end
end
