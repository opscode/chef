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

describe Chef::PolicyBuilder::Policyfile do

  let(:node_name) { "joe_node" }
  let(:ohai_data) { { "platform" => "ubuntu", "platform_version" => "13.04", "fqdn" => "joenode.example.com" } }
  let(:json_attribs) { { "custom_attr" => "custom_attr_value" } }
  let(:override_runlist) { nil }
  let(:events) { Chef::EventDispatch::Dispatcher.new }
  let(:policy_builder) { Chef::PolicyBuilder::Policyfile.new(node_name, ohai_data, json_attribs, override_runlist, events) }

  # Convert a SHA1 (160 bit) hex string into an x.y.z version number where the
  # maximum value is smaller than a postgres BIGINT (signed 64bit, so 63 usable
  # bits). This requires enterprise Chef or open source server 11.1.0+ (currently not released)
  #
  # The SHA1 is devided as follows:
  # * "major": first 14 chars (56 bits)
  # * "minor": next 14 chars (56 bits)
  # * "patch": last 12 chars (48 bits)
  def id_to_dotted(sha1_id)
    major = sha1_id[0...14]
    minor = sha1_id[14...28]
    patch = sha1_id[28..40]
    decimal_integers = [major, minor, patch].map { |hex| hex.to_i(16) }
    decimal_integers.join(".")
  end

  let(:example1_lock_data) do
    # based on https://github.com/danielsdeleo/chef-workflow2-prototype/blob/master/skeletons/basic_policy/Policyfile.lock.json
    {
      "identifier" => "168d2102fb11c9617cd8a981166c8adc30a6e915",
      "version" => "2.3.5",
      # NOTE: for compatibility mode we include the dotted id in the policyfile to enhance discoverability.
      "dotted_decimal_identifier" => id_to_dotted("168d2102fb11c9617cd8a981166c8adc30a6e915"),
      "source" => { "path" => "./cookbooks/demo" },
      "scm_identifier" => {
        "vcs" => "git",
        "rev_id" => "9d5b09026470c322c3cb5ca8a4157c4d2f16cef3",
        "remote" => nil,
      },
    }
  end

  let(:example2_lock_data) do
    {
      "identifier" => "feab40e1fca77c7360ccca1481bb8ba5f919ce3a",
      "version" => "4.2.0",
      # NOTE: for compatibility mode we include the dotted id in the policyfile to enhance discoverability.
      "dotted_decimal_identifier" => id_to_dotted("feab40e1fca77c7360ccca1481bb8ba5f919ce3a"),
      "source" => { "api" => "https://community.getchef.com/api/v1/cookbooks/example2" },
    }
  end

  let(:policyfile_default_attributes) do
    {
        "policyfile_default_attr" => "policyfile_default_value",
        "top_level_attr" => "hat",
        "baseline_attr" => {
          "one" => 1,
          "two" => 2,
          "deep" => {
              "three" => 3,
              "four" => [4],
              "five" => [5],
          },
        },
        "policy_group_value" => {
          "baseline_attr" => {
            "one" => 111,
          },
        },
      }
  end

  let(:policyfile_override_attributes) do
    {
       "policyfile_override_attr" => "policyfile_override_value",
       "baseline_attr" => {
         "deep" => {
           "three" => 333 },
       },
       "policy_group_value" => {
         "top_level_attr" => "cat",
         "baseline_attr" => {
           "deep" => {
             "four" => [444],
           },
         },
       },
    }
  end

  let(:policyfile_run_list) { ["recipe[example1::default]", "recipe[example2::server]"] }

  let(:basic_valid_policy_data) do
    {
      "name" => "example-policy",
      "revision_id" => "123abc",

      "run_list" => policyfile_run_list,

      "cookbook_locks" => {
        "example1" => example1_lock_data,
        "example2" => example2_lock_data,
      },

      "default_attributes" => policyfile_default_attributes,
      "override_attributes" => policyfile_override_attributes,
    }
  end

  let(:parsed_policyfile_json) { basic_valid_policy_data }

  let(:err_namespace) { Chef::PolicyBuilder::Policyfile }

  it "configures a Chef HTTP API client" do
    http = double("Chef::ServerAPI")
    server_url = "https://api.opscode.com/organizations/example"
    Chef::Config[:chef_server_url] = server_url
    expect(Chef::ServerAPI).to receive(:new).with(server_url, version_class: Chef::CookbookManifestVersions).and_return(http)
    expect(policy_builder.api_service).to eq(http)
  end

  describe "reporting unsupported features" do

    def initialize_pb
      Chef::PolicyBuilder::Policyfile.new(node_name, ohai_data, json_attribs, override_runlist, events)
    end

    it "always gives `false` for #temporary_policy?" do
      expect(initialize_pb.temporary_policy?).to be_falsey
    end

    context "chef-solo" do
      before { Chef::Config[:solo_legacy_mode] = true }

      it "errors on create" do
        expect { initialize_pb }.to raise_error(err_namespace::UnsupportedFeature)
      end
    end

    context "when given an override run_list" do
      let(:override_runlist) { "recipe[foo],recipe[bar]" }

      it "errors on create" do
        expect { initialize_pb }.to raise_error(err_namespace::UnsupportedFeature)
      end
    end

    context "when json_attribs contains a run_list" do
      let(:json_attribs) { { "run_list" => [] } }

      it "errors on create" do
        expect { initialize_pb }.to raise_error(err_namespace::UnsupportedFeature)
      end
    end

    context "when an environment is configured" do
      before { Chef::Config[:environment] = "blurch" }

      it "errors when an environment is configured" do
        expect { initialize_pb }.to raise_error(err_namespace::UnsupportedFeature)
      end
    end

  end

  describe "loading policy data" do

    let(:api_service) { double("Chef::ServerAPI") }

    let(:configured_environment) { nil }

    let(:override_runlist) { nil }
    let(:primary_runlist) { nil }

    let(:original_default_attrs) { { "default_key" => "default_value" } }
    let(:original_override_attrs) { { "override_key" => "override_value" } }

    let(:node) do
      node = Chef::Node.new
      node.name(node_name)
      node.default_attrs = original_default_attrs
      node.override_attrs = original_override_attrs
      node.run_list(primary_runlist) if primary_runlist
      node
    end

    before do
      allow(policy_builder).to receive(:api_service).and_return(api_service)
    end

    describe "building policy from the policyfile" do

      before do
        allow(policy_builder).to receive(:policy).and_return(parsed_policyfile_json)
      end

      it "fetches the policy file from a data bag item" do
        expect(policy_builder.policy).to eq(parsed_policyfile_json)
      end

      it "extracts the run_list from the policyfile" do
        expect(policy_builder.run_list).to eq(policyfile_run_list)
      end

      it "extracts the cookbooks and versions for display from the policyfile" do
        expected = [
          "example1::default@2.3.5 (168d210)",
          "example2::server@4.2.0 (feab40e)",
        ]

        expect(policy_builder.run_list_with_versions_for_display).to eq(expected)
      end

      it "generates a RunListExpansion-alike object for feeding to the CookbookCompiler" do
        expect(policy_builder.run_list_expansion_ish).to respond_to(:recipes)
        expect(policy_builder.run_list_expansion_ish.recipes).to eq(["example1::default", "example2::server"])
      end

      it "implements #expand_run_list in a manner compatible with ExpandNodeObject" do
        policy_builder.finish_load_node(node)
        expect(policy_builder.expand_run_list).to respond_to(:recipes)
        expect(policy_builder.expand_run_list.recipes).to eq(["example1::default", "example2::server"])
        expect(policy_builder.expand_run_list.roles).to eq([])
      end

      describe "validating the Policyfile.lock" do

        it "errors if the policyfile json contains any non-recipe items" do
          parsed_policyfile_json["run_list"] = ["role[foo]"]
          expect { policy_builder.validate_policyfile }.to raise_error(err_namespace::PolicyfileError)
        end

        it "errors if the policyfile json contains non-fully qualified recipe items" do
          parsed_policyfile_json["run_list"] = ["recipe[foo]"]
          expect { policy_builder.validate_policyfile }.to raise_error(err_namespace::PolicyfileError)
        end

        it "errors if the policyfile doesn't have a run_list key" do
          parsed_policyfile_json.delete("run_list")
          expect { policy_builder.validate_policyfile }.to raise_error(err_namespace::PolicyfileError)
        end

        it "error if the policyfile doesn't have a cookbook_locks key" do
          parsed_policyfile_json.delete("cookbook_locks")
          expect { policy_builder.validate_policyfile }.to raise_error(err_namespace::PolicyfileError)
        end

        it "accepts a valid policyfile" do
          policy_builder.validate_policyfile
        end

      end

      describe "#build_node" do

        let(:node) do
          node = Chef::Node.new
          node.name(node_name)
          node
        end

        before do
          allow(policy_builder).to receive(:node).and_return(node)
        end

        context "when the run is successful" do
          let(:run_list) do
            ["recipe[test::default]",
             "recipe[test::other]"]
          end

          let(:version_hash) do
            {
              "version" => "0.1.0",
              "identifier" => "012345678",
            }
          end

          let(:run_list_for_data_collector) do
            {
              id: "_policy_node",
              run_list: [
               { type: "recipe", name: "test::default", skipped: false, version: nil },
               { type: "recipe", name: "test::other", skipped: false, version: nil },
              ],
            }
          end

          before do
            allow(policy_builder).to receive(:run_list)
              .and_return(run_list)
            allow(policy_builder).to receive(:cookbook_lock_for)
              .and_return(version_hash)
          end

          it "sends the run_list_expanded event" do
            policy_builder.build_node
            expect(policy_builder.run_list_expansion_ish.to_hash)
              .to eq(run_list_for_data_collector)
          end
        end
      end

      describe "building the node object" do

        let(:extra_chef_config) { {} }

        before do
          # must be set before #build_node is called to have the proper effect
          extra_chef_config.each do |key, value|
            Chef::Config[key] = value
          end

          policy_builder.finish_load_node(node)
          policy_builder.build_node
        end

        # it sets policy_name and policy_group in the following priority order:
        # -j JSON > config file > node object

        describe "selecting policy_name and policy_group from the various sources" do

          context "when only set in node JSON" do

            let(:json_attribs) do
              {
                "policy_name" => "policy_name_from_node_json",
                "policy_group" => "policy_group_from_node_json",
              }
            end

            it "sets policy_name and policy_group on Chef::Config" do
              expect(Chef::Config[:policy_name]).to eq("policy_name_from_node_json")
              expect(Chef::Config[:policy_group]).to eq("policy_group_from_node_json")
            end

            it "sets policy_name and policy_group on the node object" do
              expect(node.policy_name).to eq("policy_name_from_node_json")
              expect(node.policy_group).to eq("policy_group_from_node_json")
            end

          end

          context "when only set in Chef::Config" do

            let(:extra_chef_config) do
              {
                policy_name: "policy_name_from_config",
                policy_group: "policy_group_from_config",
              }
            end

            it "sets policy_name and policy_group on the node object" do
              expect(node.policy_name).to eq("policy_name_from_config")
              expect(node.policy_group).to eq("policy_group_from_config")
            end

          end

          context "when only set on the node" do

            let(:node) do
              node = Chef::Node.new
              node.name(node_name)
              node.policy_name = "policy_name_from_node"
              node.policy_group = "policy_group_from_node"
              node
            end

            it "sets policy_name and policy_group on Chef::Config" do
              expect(Chef::Config[:policy_name]).to eq("policy_name_from_node")
              expect(Chef::Config[:policy_group]).to eq("policy_group_from_node")
            end

          end

          context "when set in Chef::Config and the fetched node" do

            let(:node) do
              node = Chef::Node.new
              node.name(node_name)
              node.policy_name = "policy_name_from_node"
              node.policy_group = "policy_group_from_node"
              node
            end

            let(:extra_chef_config) do
              {
                policy_name: "policy_name_from_config",
                policy_group: "policy_group_from_config",
              }
            end

            it "prefers the policy_name and policy_group from Chef::Config" do
              expect(node.policy_name).to eq("policy_name_from_config")
              expect(node.policy_group).to eq("policy_group_from_config")
            end

          end

          context "when set in node json and the fetched node" do

            let(:json_attribs) do
              {
                "policy_name" => "policy_name_from_node_json",
                "policy_group" => "policy_group_from_node_json",
              }
            end

            let(:node) do
              node = Chef::Node.new
              node.name(node_name)
              node.policy_name = "policy_name_from_node"
              node.policy_group = "policy_group_from_node"
              node
            end

            it "prefers the policy_name and policy_group from the node json" do
              expect(policy_builder.policy_name).to eq("policy_name_from_node_json")
              expect(policy_builder.policy_group).to eq("policy_group_from_node_json")

              expect(Chef::Config[:policy_name]).to eq("policy_name_from_node_json")
              expect(Chef::Config[:policy_group]).to eq("policy_group_from_node_json")
              expect(node.policy_name).to eq("policy_name_from_node_json")
              expect(node.policy_group).to eq("policy_group_from_node_json")
            end

          end

          context "when set in all sources" do

            let(:json_attribs) do
              {
                "policy_name" => "policy_name_from_node_json",
                "policy_group" => "policy_group_from_node_json",
              }
            end

            let(:node) do
              node = Chef::Node.new
              node.name(node_name)
              node.policy_name = "policy_name_from_node"
              node.policy_group = "policy_group_from_node"
              node
            end

            let(:extra_chef_config) do
              {
                policy_name: "policy_name_from_config",
                policy_group: "policy_group_from_config",
              }
            end

            it "prefers the policy_name and group from node json" do
              expect(policy_builder.policy_name).to eq("policy_name_from_node_json")
              expect(policy_builder.policy_group).to eq("policy_group_from_node_json")

              expect(Chef::Config[:policy_name]).to eq("policy_name_from_node_json")
              expect(Chef::Config[:policy_group]).to eq("policy_group_from_node_json")
              expect(node.policy_name).to eq("policy_name_from_node_json")
              expect(node.policy_group).to eq("policy_group_from_node_json")
              expect(node.automatic_attrs[:policy_name]).to eq("policy_name_from_node_json")
              expect(node.automatic_attrs[:policy_group]).to eq("policy_group_from_node_json")
              expect(node.automatic_attrs[:chef_environment]).to eq("policy_group_from_node_json")

            end

          end

        end

        it "resets default and override data" do
          expect(node["default_key"]).to be_nil
          expect(node["override_key"]).to be_nil
        end

        describe "setting attribute values" do

          before do
            policy_builder.build_node
          end

          it "resets default and override data" do
            expect(node["default_key"]).to be_nil
            expect(node["override_key"]).to be_nil
          end

          it "applies ohai data" do
            expect(ohai_data).to_not be_empty # ensure test is testing something
            ohai_data.each do |key, value|
              expect(node.automatic_attrs[key]).to eq(value)
            end
          end

          it "applies attributes from json file" do
            expect(node["custom_attr"]).to eq("custom_attr_value")
          end

          it "applies attributes from the policyfile" do
            expect(node["policyfile_default_attr"]).to eq("policyfile_default_value")
            expect(node["policyfile_override_attr"]).to eq("policyfile_override_value")
          end

          it "sets the policyfile's run_list on the node object" do
            expect(node.run_list).to eq(policyfile_run_list)
          end

          it "creates node.automatic_attrs[:roles]" do
            expect(node.automatic_attrs[:roles]).to eq([])
          end

          it "create node.automatic_attrs[:recipes]" do
            expect(node.automatic_attrs[:recipes]).to eq(["example1::default", "example2::server"])
          end

        end

        context "when a named run_list is given" do

          before do
            Chef::Config[:named_run_list] = "deploy-app"
          end

          context "and the named run_list is not present in the policy" do

            it "raises a ConfigurationError" do
              err_class = Chef::PolicyBuilder::Policyfile::ConfigurationError
              err_text = "Policy 'example-policy' revision '123abc' does not have named_run_list 'deploy-app'(available named_run_lists: [])"
              expect { policy_builder.build_node }.to raise_error(err_class, err_text)
            end

          end

          context "and the named run_list is present in the policy" do

            let(:parsed_policyfile_json) do
              basic_valid_policy_data.dup.tap do |p|
                p["named_run_lists"] = {
                  "deploy-app" => [ "recipe[example1::default]" ],
                }
              end
            end

            before do
              policy_builder.build_node
            end

            it "sets the run list to the desired named run list" do
              expect(policy_builder.run_list).to eq([ "recipe[example1::default]" ])
              expected_expansion = Chef::PolicyBuilder::Policyfile::RunListExpansionIsh.new([ "example1::default" ], [])
              expect(policy_builder.run_list_expansion).to eq(expected_expansion)
              expect(policy_builder.run_list_with_versions_for_display).to eq(["example1::default@2.3.5 (168d210)"])
              expect(node.run_list).to eq([ Chef::RunList::RunListItem.new("recipe[example1::default]") ])
              expect(node[:roles]).to eq( [] )
              expect(node[:recipes]).to eq( ["example1::default"] )
            end

            it "disables the cookbook cache cleaner" do
              expect(Chef::CookbookCacheCleaner.instance.skip_removal).to be(true)
            end

          end

        end

        describe "hoisting attribute values" do
          context "with no policy group set" do
            it "does not hoist policy_group specific attributes" do
              expect( node["top_level_attr"] ).to eql("hat")
              expect( node["baseline_attr"]["one"] ).to eql(1)
              expect( node["baseline_attr"]["two"] ).to eql(2)
              expect( node["baseline_attr"]["deep"]["three"] ).to eql(333)
              expect( node["baseline_attr"]["deep"]["four"] ).to eql([4])
              expect( node["baseline_attr"]["deep"]["five"] ).to eql([5])
            end
          end

          context "with a policy group set" do
            before do
              Chef::Config[:policy_group] = "policy_group_value"
              policy_builder.finish_load_node(node)
              policy_builder.build_node
            end

            it "hoists default attributes" do
              expect( node["top_level_attr"] ).to eql("cat")
              expect( node["baseline_attr"]["one"]).to eql(111)
              expect( node["baseline_attr"]["two"] ).to eql(2)
              expect( node["baseline_attr"]["deep"]["five"] ).to eql([5])
            end

            it "hoists override attributes" do
              expect( node["top_level_attr"] ).to eql("cat")
              expect( node["baseline_attr"]["two"] ).to eql(2)
              expect( node["baseline_attr"]["deep"]["three"] ).to eql(333)
              expect( node["baseline_attr"]["deep"]["four"] ).to eql([444])
              expect( node["baseline_attr"]["deep"]["five"] ).to eql([5])
            end
          end
        end
      end

      describe "fetching the desired cookbook set" do

        let(:example1_cookbook_data) { double("CookbookVersion Hash for example1 cookbook") }
        let(:example2_cookbook_data) { double("CookbookVersion Hash for example2 cookbook") }

        let(:example1_cookbook_object) { double("Chef::CookbookVersion for example1 cookbook", version: "0.1.2") }
        let(:example2_cookbook_object) { double("Chef::CookbookVersion for example2 cookbook", version: "1.2.3") }

        let(:expected_cookbook_hash) do
          { "example1" => example1_cookbook_object, "example2" => example2_cookbook_object }
        end

        let(:example1_xyz_version) { example1_lock_data["dotted_decimal_identifier"] }
        let(:example2_xyz_version) { example2_lock_data["dotted_decimal_identifier"] }

        let(:example1_identifier) { example1_lock_data["identifier"] }
        let(:example2_identifier) { example2_lock_data["identifier"] }

        let(:cookbook_synchronizer) { double("Chef::CookbookSynchronizer") }

        shared_examples "fetching cookbooks when they don't exist" do
          context "and a cookbook is missing" do

            let(:error404) { Net::HTTPClientException.new("404 message", :body) }

            before do
              policy_builder.finish_load_node(node)
              policy_builder.build_node

              expect(api_service).to receive(:get).with(cookbook1_url)
                .and_raise(error404)
            end

            it "raises an error indicating which cookbook is missing" do
              expect { policy_builder.cookbooks_to_sync }.to raise_error(Chef::Exceptions::CookbookNotFound)
            end

          end
        end

        shared_examples_for "fetching cookbooks when they exist" do
          context "and the cookbooks can be fetched" do
            before do
              Chef.reset!

              policy_builder.finish_load_node(node)
              policy_builder.build_node

              allow(Chef::CookbookSynchronizer).to receive(:new)
                .with(expected_cookbook_hash, events)
                .and_return(cookbook_synchronizer)
            end

            after do
              Chef.reset!
            end

            it "builds a Hash of the form 'cookbook_name' => Chef::CookbookVersion" do
              expect(policy_builder.cookbooks_to_sync).to eq(expected_cookbook_hash)
            end

            it "syncs the desired cookbooks via CookbookSynchronizer" do
              expect(cookbook_synchronizer).to receive(:sync_cookbooks)
              policy_builder.sync_cookbooks
            end

            it "builds a run context" do
              expect(cookbook_synchronizer).to receive(:sync_cookbooks)
              expect_any_instance_of(Chef::RunContext).to receive(:load).with(policy_builder.run_list_expansion_ish)
              expect_any_instance_of(Chef::CookbookCollection).to receive(:validate!)
              expect_any_instance_of(Chef::CookbookCollection).to receive(:install_gems)
              run_context = policy_builder.setup_run_context
              expect(run_context.node).to eq(node)
              expect(run_context.cookbook_collection.keys).to match_array(%w{example1 example2})
            end

            it "makes the run context available via static method on Chef" do
              expect(cookbook_synchronizer).to receive(:sync_cookbooks)
              expect_any_instance_of(Chef::RunContext).to receive(:load).with(policy_builder.run_list_expansion_ish)
              expect_any_instance_of(Chef::CookbookCollection).to receive(:validate!)
              expect_any_instance_of(Chef::CookbookCollection).to receive(:install_gems)
              run_context = policy_builder.setup_run_context
              expect(Chef.run_context).to eq(run_context)
            end

          end
        end # shared_examples_for "fetching cookbooks"

        before do
          Chef::Config[:policy_name] = "example"
          Chef::Config[:policy_group] = "policy-stage"
        end

        let(:cookbook1_url) { "cookbook_artifacts/example1/#{example1_identifier}" }
        let(:cookbook2_url) { "cookbook_artifacts/example2/#{example2_identifier}" }

        context "when the cookbooks don't exist on the server" do
          include_examples "fetching cookbooks when they don't exist"
        end

        context "when the cookbooks exist on the server" do

          before do
            expect(api_service).to receive(:get).with(cookbook1_url)
              .and_return(example1_cookbook_data)
            expect(api_service).to receive(:get).with(cookbook2_url)
              .and_return(example2_cookbook_data)

            expect(Chef::CookbookVersion).to receive(:from_cb_artifact_data).with(example1_cookbook_data)
              .and_return(example1_cookbook_object)
            expect(Chef::CookbookVersion).to receive(:from_cb_artifact_data).with(example2_cookbook_data)
              .and_return(example2_cookbook_object)
          end

          include_examples "fetching cookbooks when they exist"

        end

      end
    end

  end

end
