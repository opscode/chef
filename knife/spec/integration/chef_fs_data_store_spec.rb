#
# Author:: John Keiser (<jkeiser@chef.io>)
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

require "knife_spec_helper"
require "support/shared/integration/integration_helper"
require "chef/knife/list"
require "chef/knife/delete"
require "chef/knife/show"
require "chef/knife/raw"
require "chef/knife/cookbook_upload"

describe "ChefFSDataStore tests", :workstation do
  include IntegrationSupport
  include KnifeSupport

  let(:cookbook_x_100_metadata_rb) { cb_metadata("x", "1.0.0") }
  let(:cookbook_z_100_metadata_rb) { cb_metadata("z", "1.0.0") }

  describe "with repo mode 'hosted_everything' (default)" do
    when_the_repository "has one of each thing" do
      before do
        file "clients/x.json", {}
        file "cookbook_artifacts/x-111/metadata.rb", cookbook_x_100_metadata_rb
        file "cookbooks/x/metadata.rb", cookbook_x_100_metadata_rb
        file "data_bags/x/y.json", {}
        file "environments/x.json", {}
        file "nodes/x.json", {}
        file "roles/x.json", {}
        # file "users/x.json", {}
        file "containers/x.json", {}
        file "groups/x.json", {}
        file "containers/x.json", {}
        file "groups/x.json", {}
        file "policies/x-111.json", {}
        file "policy_groups/x.json", {}
      end

      context "GET /TYPE" do
        it "knife list -z -R returns everything" do
          knife("list -z -Rfp /").should_succeed <<~EOM
            /acls/
            /acls/clients/
            /acls/clients/x.json
            /acls/containers/
            /acls/containers/x.json
            /acls/cookbook_artifacts/
            /acls/cookbook_artifacts/x.json
            /acls/cookbooks/
            /acls/cookbooks/x.json
            /acls/data_bags/
            /acls/data_bags/x.json
            /acls/environments/
            /acls/environments/x.json
            /acls/groups/
            /acls/groups/x.json
            /acls/nodes/
            /acls/nodes/x.json
            /acls/organization.json
            /acls/policies/
            /acls/policies/x.json
            /acls/policy_groups/
            /acls/policy_groups/x.json
            /acls/roles/
            /acls/roles/x.json
            /clients/
            /clients/x.json
            /containers/
            /containers/x.json
            /cookbook_artifacts/
            /cookbook_artifacts/x-111/
            /cookbook_artifacts/x-111/metadata.rb
            /cookbooks/
            /cookbooks/x/
            /cookbooks/x/metadata.rb
            /data_bags/
            /data_bags/x/
            /data_bags/x/y.json
            /environments/
            /environments/x.json
            /groups/
            /groups/x.json
            /invitations.json
            /members.json
            /nodes/
            /nodes/x.json
            /org.json
            /policies/
            /policies/x-111.json
            /policy_groups/
            /policy_groups/x.json
            /roles/
            /roles/x.json
          EOM
        end
      end

      context "DELETE /TYPE/NAME" do
        it "knife delete -z /clients/x.json works" do
          knife("delete -z /clients/x.json").should_succeed "Deleted /clients/x.json\n"
          knife("list -z -Rfp /clients").should_succeed ""
        end

        it "knife delete -z -r /cookbooks/x works" do
          knife("delete -z -r /cookbooks/x").should_succeed "Deleted /cookbooks/x\n"
          knife("list -z -Rfp /cookbooks").should_succeed ""
        end

        it "knife delete -z -r /data_bags/x works" do
          knife("delete -z -r /data_bags/x").should_succeed "Deleted /data_bags/x\n"
          knife("list -z -Rfp /data_bags").should_succeed ""
        end

        it "knife delete -z /data_bags/x/y.json works" do
          knife("delete -z /data_bags/x/y.json").should_succeed "Deleted /data_bags/x/y.json\n"
          knife("list -z -Rfp /data_bags").should_succeed "/data_bags/x/\n"
        end

        it "knife delete -z /environments/x.json works" do
          knife("delete -z /environments/x.json").should_succeed "Deleted /environments/x.json\n"
          knife("list -z -Rfp /environments").should_succeed ""
        end

        it "knife delete -z /nodes/x.json works" do
          knife("delete -z /nodes/x.json").should_succeed "Deleted /nodes/x.json\n"
          knife("list -z -Rfp /nodes").should_succeed ""
        end

        it "knife delete -z /roles/x.json works" do
          knife("delete -z /roles/x.json").should_succeed "Deleted /roles/x.json\n"
          knife("list -z -Rfp /roles").should_succeed ""
        end

      end

      context "GET /TYPE/NAME" do
        it "knife show -z /clients/x.json works" do
          knife("show -z /clients/x.json").should_succeed( /"x"/ )
        end

        it "knife show -z /cookbooks/x/metadata.rb works" do
          knife("show -z /cookbooks/x/metadata.rb").should_succeed "/cookbooks/x/metadata.rb:\n#{cookbook_x_100_metadata_rb}\n"
        end

        it "knife show -z /data_bags/x/y.json works" do
          knife("show -z /data_bags/x/y.json").should_succeed( /"y"/ )
        end

        it "knife show -z /environments/x.json works" do
          knife("show -z /environments/x.json").should_succeed( /"x"/ )
        end

        it "knife show -z /nodes/x.json works" do
          knife("show -z /nodes/x.json").should_succeed( /"x"/ )
        end

        it "knife show -z /roles/x.json works" do
          knife("show -z /roles/x.json").should_succeed( /"x"/ )
        end

      end

      context "PUT /TYPE/NAME" do
        before do
          file "empty.json", {}
          file "dummynode.json", { "name" => "x", "chef_environment" => "rspec" , "json_class" => "Chef::Node", "normal" => { "foo" => "bar" } }
          file "rolestuff.json", '{"description":"hi there","name":"x"}'
          file "cookbooks_to_upload/x/metadata.rb", cookbook_x_100_metadata_rb
        end

        it "knife raw -z -i empty.json -m PUT /clients/x" do
          knife("raw -z -i #{path_to("empty.json")} -m PUT /clients/x").should_succeed( /"x"/ )
          knife("list --local /clients").should_succeed "/clients/x.json\n"
        end

        it "knife cookbook upload works" do
          knife("cookbook upload -z --cookbook-path #{path_to("cookbooks_to_upload")} x").should_succeed stderr: <<~EOM
            Uploading x              [1.0.0]
            Uploaded 1 cookbook.
          EOM
          knife("list --local -Rfp /cookbooks").should_succeed "/cookbooks/x/\n/cookbooks/x/metadata.json\n/cookbooks/x/metadata.rb\n"
        end

        it "knife raw -z -i empty.json -m PUT /data/x/y" do
          knife("raw -z -i #{path_to("empty.json")} -m PUT /data/x/y").should_succeed( /"y"/ )
          knife("list --local -Rfp /data_bags").should_succeed "/data_bags/x/\n/data_bags/x/y.json\n"
        end

        it "knife raw -z -i empty.json -m PUT /environments/x" do
          knife("raw -z -i #{path_to("empty.json")} -m PUT /environments/x").should_succeed( /"x"/ )
          knife("list --local /environments").should_succeed "/environments/x.json\n"
        end

        it "knife raw -z -i dummynode.json -m PUT /nodes/x" do
          knife("raw -z -i #{path_to("dummynode.json")} -m PUT /nodes/x").should_succeed( /"x"/ )
          knife("list --local /nodes").should_succeed "/nodes/x.json\n"
          knife("show -z /nodes/x.json --verbose").should_succeed(/"bar"/)
        end

        it "knife raw -z -i empty.json -m PUT /roles/x" do
          knife("raw -z -i #{path_to("empty.json")} -m PUT /roles/x").should_succeed( /"x"/ )
          knife("list --local /roles").should_succeed "/roles/x.json\n"
        end

        it "After knife raw -z -i rolestuff.json -m PUT /roles/x, the output is pretty" do
          knife("raw -z -i #{path_to("rolestuff.json")} -m PUT /roles/x").should_succeed( /"x"/ )
          expect(IO.read(path_to("roles/x.json"))).to eq <<~EOM.strip
            {
              "name": "x",
              "description": "hi there"
            }
          EOM
        end
      end
    end

    when_the_repository "is empty" do
      context "POST /TYPE/NAME" do
        before do
          file "empty.json", { "name" => "z" }
          file "dummynode.json", { "name" => "z", "chef_environment" => "rspec" , "json_class" => "Chef::Node", "normal" => { "foo" => "bar" } }
          file "empty_x.json", { "name" => "x" }
          file "empty_id.json", { "id" => "z" }
          file "rolestuff.json", '{"description":"hi there","name":"x"}'
          file "cookbooks_to_upload/z/metadata.rb", cookbook_z_100_metadata_rb
        end

        it "knife raw -z -i empty.json -m POST /clients" do
          knife("raw -z -i #{path_to("empty.json")} -m POST /clients").should_succeed( /uri/ )
          knife("list --local /clients").should_succeed "/clients/z.json\n"
        end

        it "knife cookbook upload works" do
          knife("cookbook upload -z --cookbook-path #{path_to("cookbooks_to_upload")} z").should_succeed stderr: <<~EOM
            Uploading z            [1.0.0]
            Uploaded 1 cookbook.
          EOM
          knife("list --local -Rfp /cookbooks").should_succeed "/cookbooks/z/\n/cookbooks/z/metadata.json\n/cookbooks/z/metadata.rb\n"
        end

        it "knife raw -z -i empty.json -m POST /data" do
          knife("raw -z -i #{path_to("empty.json")} -m POST /data").should_succeed( /uri/ )
          knife("list --local -Rfp /data_bags").should_succeed "/data_bags/z/\n"
        end

        it "knife raw -z -i empty.json -m POST /data/x" do
          knife("raw -z -i #{path_to("empty_x.json")} -m POST /data").should_succeed( /uri/ )
          knife("raw -z -i #{path_to("empty_id.json")} -m POST /data/x").should_succeed( /"z"/ )
          knife("list --local -Rfp /data_bags").should_succeed "/data_bags/x/\n/data_bags/x/z.json\n"
        end

        it "knife raw -z -i empty.json -m POST /environments" do
          knife("raw -z -i #{path_to("empty.json")} -m POST /environments").should_succeed( /uri/ )
          knife("list --local /environments").should_succeed "/environments/z.json\n"
        end

        it "knife raw -z -i dummynode.json -m POST /nodes" do
          knife("raw -z -i #{path_to("dummynode.json")} -m POST /nodes").should_succeed( /uri/ )
          knife("list --local /nodes").should_succeed "/nodes/z.json\n"
          knife("show -z /nodes/z.json").should_succeed(/"bar"/)
        end

        it "knife raw -z -i empty.json -m POST /roles" do
          knife("raw -z -i #{path_to("empty.json")} -m POST /roles").should_succeed( /uri/ )
          knife("list --local /roles").should_succeed "/roles/z.json\n"
        end

        it "After knife raw -z -i rolestuff.json -m POST /roles, the output is pretty" do
          knife("raw -z -i #{path_to("rolestuff.json")} -m POST /roles").should_succeed( /uri/ )
          expect(IO.read(path_to("roles/x.json"))).to eq <<~EOM.strip
            {
              "name": "x",
              "description": "hi there"
            }
          EOM
        end
      end

      it "knife list -z -R returns nothing" do
        knife("list -z -Rfp /").should_succeed <<~EOM
          /acls/
          /acls/clients/
          /acls/containers/
          /acls/cookbook_artifacts/
          /acls/cookbooks/
          /acls/data_bags/
          /acls/environments/
          /acls/groups/
          /acls/nodes/
          /acls/organization.json
          /acls/policies/
          /acls/policy_groups/
          /acls/roles/
          /clients/
          /containers/
          /cookbook_artifacts/
          /cookbooks/
          /data_bags/
          /environments/
          /groups/
          /invitations.json
          /members.json
          /nodes/
          /org.json
          /policies/
          /policy_groups/
          /roles/
        EOM
      end

      context "DELETE /TYPE/NAME" do
        it "knife delete -z /clients/x.json fails with an error" do
          knife("delete -z /clients/x.json").should_fail "ERROR: /clients/x.json: No such file or directory\n"
        end

        it "knife delete -z -r /cookbooks/x fails with an error" do
          knife("delete -z -r /cookbooks/x").should_fail "ERROR: /cookbooks/x: No such file or directory\n"
        end

        it "knife delete -z -r /data_bags/x fails with an error" do
          knife("delete -z -r /data_bags/x").should_fail "ERROR: /data_bags/x: No such file or directory\n"
        end

        it "knife delete -z /data_bags/x/y.json fails with an error" do
          knife("delete -z /data_bags/x/y.json").should_fail "ERROR: /data_bags/x/y.json: No such file or directory\n"
        end

        it "knife delete -z /environments/x.json fails with an error" do
          knife("delete -z /environments/x.json").should_fail "ERROR: /environments/x.json: No such file or directory\n"
        end

        it "knife delete -z /nodes/x.json fails with an error" do
          knife("delete -z /nodes/x.json").should_fail "ERROR: /nodes/x.json: No such file or directory\n"
        end

        it "knife delete -z /roles/x.json fails with an error" do
          knife("delete -z /roles/x.json").should_fail "ERROR: /roles/x.json: No such file or directory\n"
        end

      end

      context "GET /TYPE/NAME" do
        it "knife show -z /clients/x.json fails with an error" do
          knife("show -z /clients/x.json").should_fail "ERROR: /clients/x.json: No such file or directory\n"
        end

        it "knife show -z /cookbooks/x/metadata.rb fails with an error" do
          knife("show -z /cookbooks/x/metadata.rb").should_fail "ERROR: /cookbooks/x/metadata.rb: No such file or directory\n"
        end

        it "knife show -z /data_bags/x/y.json fails with an error" do
          knife("show -z /data_bags/x/y.json").should_fail "ERROR: /data_bags/x/y.json: No such file or directory\n"
        end

        it "knife show -z /environments/x.json fails with an error" do
          knife("show -z /environments/x.json").should_fail "ERROR: /environments/x.json: No such file or directory\n"
        end

        it "knife show -z /nodes/x.json fails with an error" do
          knife("show -z /nodes/x.json").should_fail "ERROR: /nodes/x.json: No such file or directory\n"
        end

        it "knife show -z /roles/x.json fails with an error" do
          knife("show -z /roles/x.json").should_fail "ERROR: /roles/x.json: No such file or directory\n"
        end

      end

      context "PUT /TYPE/NAME" do
        before do
          file "empty.json", {}
        end

        it "knife raw -z -i empty.json -m PUT /clients/x fails with 404" do
          knife("raw -z -i #{path_to("empty.json")} -m PUT /clients/x").should_fail( /404/ )
        end

        it "knife raw -z -i empty.json -m PUT /data/x/y fails with 404" do
          knife("raw -z -i #{path_to("empty.json")} -m PUT /data/x/y").should_fail( /404/ )
        end

        it "knife raw -z -i empty.json -m PUT /environments/x fails with 404" do
          knife("raw -z -i #{path_to("empty.json")} -m PUT /environments/x").should_fail( /404/ )
        end

        it "knife raw -z -i empty.json -m PUT /nodes/x fails with 404" do
          knife("raw -z -i #{path_to("empty.json")} -m PUT /nodes/x").should_fail( /404/ )
        end

        it "knife raw -z -i empty.json -m PUT /roles/x fails with 404" do
          knife("raw -z -i #{path_to("empty.json")} -m PUT /roles/x").should_fail( /404/ )
        end

      end
    end
  end

  # We have to configure Zero for Chef 11 mode in order to test users because:
  # 1. local mode overrides your `chef_server_url` to something like "http://localhost:PORT"
  # 2. single org mode maps requests like "https://localhost:PORT/users" so
  #   they're functionally equivalent to "https://localhost:PORT/organizations/DEFAULT/users"
  # 3. Users are global objects in Chef 12, and should be accessed at URLs like
  #   "https://localhost:PORT/users" (there is an org-specific users endpoint,
  #   but it's for listing users in an org, not for managing users).
  # 4. Therefore you can't hit the _real_ users endpoint in local mode when
  #   configured for Chef Server 12 mode.
  #
  # Because of this, we have to configure Zero for Chef 11 OSC mode in order to
  # test the users part of the data store with local mode.
  describe "with repo mode 'everything'" do
    before do
      Chef::Config.repo_mode = "everything"
    end

    when_the_repository "has one of each thing" do
      before do
        file "clients/x.json", {}
        file "cookbooks/x/metadata.rb", cookbook_x_100_metadata_rb
        file "data_bags/x/y.json", {}
        file "environments/x.json", {}
        file "nodes/x.json", {}
        file "roles/x.json", {}
        file "users/x.json", {}
      end

      context "GET /TYPE" do
        it "knife list -z -R returns everything" do
          knife("list -z -Rfp /").should_succeed <<~EOM
            /clients/
            /clients/x.json
            /cookbooks/
            /cookbooks/x/
            /cookbooks/x/metadata.rb
            /data_bags/
            /data_bags/x/
            /data_bags/x/y.json
            /environments/
            /environments/x.json
            /nodes/
            /nodes/x.json
            /roles/
            /roles/x.json
            /users/
            /users/x.json
          EOM
        end
      end

      context "DELETE /TYPE/NAME" do
        it "knife delete -z /users/x.json works" do
          knife("delete -z /users/x.json").should_succeed "Deleted /users/x.json\n"
          knife("list -z -Rfp /users").should_succeed ""
        end
      end

      context "GET /TYPE/NAME" do
        it "knife show -z /users/x.json works" do
          knife("show -z /users/x.json").should_succeed( /"x"/ )
        end
      end

      context "PUT /TYPE/NAME" do
        before do
          file "empty.json", {}
          file "dummynode.json", { "name" => "x", "chef_environment" => "rspec" , "json_class" => "Chef::Node", "normal" => { "foo" => "bar" } }
          file "rolestuff.json", '{"description":"hi there","name":"x"}'
          file "cookbooks_to_upload/x/metadata.rb", cookbook_x_100_metadata_rb
        end

        it "knife raw -z -i empty.json -m PUT /users/x" do
          knife("raw -z -i #{path_to("empty.json")} -m PUT /users/x").should_succeed( /"x"/ )
          knife("list --local /users").should_succeed "/users/x.json\n"
        end

        it "After knife raw -z -i rolestuff.json -m PUT /roles/x, the output is pretty" do
          knife("raw -z -i #{path_to("rolestuff.json")} -m PUT /roles/x").should_succeed( /"x"/ )
          expect(IO.read(path_to("roles/x.json"))).to eq <<~EOM.strip
            {
              "name": "x",
              "description": "hi there"
            }
          EOM
        end
      end
    end

    when_the_repository "is empty" do
      context "POST /TYPE/NAME" do
        before do
          file "empty.json", { "name" => "z" }
          file "dummynode.json", { "name" => "z", "chef_environment" => "rspec" , "json_class" => "Chef::Node", "normal" => { "foo" => "bar" } }
          file "empty_x.json", { "name" => "x" }
          file "empty_id.json", { "id" => "z" }
          file "rolestuff.json", '{"description":"hi there","name":"x"}'
          file "cookbooks_to_upload/z/metadata.rb", cookbook_z_100_metadata_rb
        end

        it "knife raw -z -i empty.json -m POST /users" do
          knife("raw -z -i #{path_to("empty.json")} -m POST /users").should_succeed( /uri/ )
          knife("list --local /users").should_succeed "/users/z.json\n"
        end
      end

      it "knife list -z -R returns nothing" do
        knife("list -z -Rfp /").should_succeed <<~EOM
          /clients/
          /cookbooks/
          /data_bags/
          /environments/
          /nodes/
          /roles/
          /users/
        EOM
      end

      context "DELETE /TYPE/NAME" do
        it "knife delete -z /users/x.json fails with an error" do
          knife("delete -z /users/x.json").should_fail "ERROR: /users/x.json: No such file or directory\n"
        end
      end

      context "GET /TYPE/NAME" do
        it "knife show -z /users/x.json fails with an error" do
          knife("show -z /users/x.json").should_fail "ERROR: /users/x.json: No such file or directory\n"
        end
      end

      context "PUT /TYPE/NAME" do
        before do
          file "empty.json", {}
        end

        it "knife raw -z -i empty.json -m PUT /users/x fails with 404" do
          knife("raw -z -i #{path_to("empty.json")} -m PUT /users/x").should_fail( /404/ )
        end
      end
    end
  end
end
