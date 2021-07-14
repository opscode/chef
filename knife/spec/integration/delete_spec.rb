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
require "chef/knife/delete"
require "chef/knife/list"
require "chef/knife/raw"

describe "knife delete", :workstation do
  include IntegrationSupport
  include KnifeSupport

  let :everything do
    <<~EOM
      /clients
      /clients/x.json
      /cookbooks
      /cookbooks/x
      /cookbooks/x/metadata.rb
      /data_bags
      /data_bags/x
      /data_bags/x/y.json
      /environments
      /environments/_default.json
      /environments/x.json
      /nodes
      /nodes/x.json
      /roles
      /roles/x.json
      /users
      /users/x.json
    EOM
  end

  let :server_everything do
    <<~EOM
      /clients
      /clients/chef-validator.json
      /clients/chef-webui.json
      /clients/x.json
      /cookbooks
      /cookbooks/x
      /cookbooks/x/metadata.rb
      /data_bags
      /data_bags/x
      /data_bags/x/y.json
      /environments
      /environments/_default.json
      /environments/x.json
      /nodes
      /nodes/x.json
      /roles
      /roles/x.json
      /users
      /users/admin.json
      /users/x.json
    EOM
  end
  let :server_nothing do
    <<~EOM
      /clients
      /clients/chef-validator.json
      /clients/chef-webui.json
      /cookbooks
      /data_bags
      /environments
      /environments/_default.json
      /nodes
      /roles
      /users
      /users/admin.json
    EOM
  end

  let :nothing do
    <<~EOM
      /clients
      /cookbooks
      /data_bags
      /environments
      /nodes
      /roles
      /users
    EOM
  end

  when_the_chef_server "has one of each thing" do
    before do
      client "x", "{}"
      cookbook "x", "1.0.0"
      data_bag "x", { "y" => "{}" }
      environment "x", "{}"
      node "x", "{}"
      role "x", "{}"
      user "x", "{}"
    end

    when_the_repository "also has one of each thing" do
      before do
        file "clients/x.json", {}
        file "cookbooks/x/metadata.rb", ""
        file "data_bags/x/y.json", {}
        file "environments/_default.json", {}
        file "environments/x.json", {}
        file "nodes/x.json", {}
        file "roles/x.json", {}
        file "users/x.json", {}
      end

      it "knife delete --both /cookbooks/x fails" do
        knife("delete --both /cookbooks/x").should_fail <<~EOM
          ERROR: /cookbooks/x (remote) must be deleted recursively!  Pass -r to knife delete.
          ERROR: /cookbooks/x (local) must be deleted recursively!  Pass -r to knife delete.
        EOM
        knife("list -Rf /").should_succeed server_everything
        knife("list -Rf --local /").should_succeed everything
      end

      it "knife delete --both -r /cookbooks/x deletes x" do
        knife("delete --both -r /cookbooks/x").should_succeed "Deleted /cookbooks/x\n"
        knife("list -Rf /").should_succeed <<~EOM
          /clients
          /clients/chef-validator.json
          /clients/chef-webui.json
          /clients/x.json
          /cookbooks
          /data_bags
          /data_bags/x
          /data_bags/x/y.json
          /environments
          /environments/_default.json
          /environments/x.json
          /nodes
          /nodes/x.json
          /roles
          /roles/x.json
          /users
          /users/admin.json
          /users/x.json
        EOM
        knife("list -Rf --local /").should_succeed <<~EOM
          /clients
          /clients/x.json
          /cookbooks
          /data_bags
          /data_bags/x
          /data_bags/x/y.json
          /environments
          /environments/_default.json
          /environments/x.json
          /nodes
          /nodes/x.json
          /roles
          /roles/x.json
          /users
          /users/x.json
        EOM
      end

      it "knife delete -r --local /cookbooks/x deletes x locally but not remotely" do
        knife("delete -r --local /cookbooks/x").should_succeed "Deleted /cookbooks/x\n"
        knife("list -Rf /").should_succeed server_everything
        knife("list -Rf --local /").should_succeed <<~EOM
          /clients
          /clients/x.json
          /cookbooks
          /data_bags
          /data_bags/x
          /data_bags/x/y.json
          /environments
          /environments/_default.json
          /environments/x.json
          /nodes
          /nodes/x.json
          /roles
          /roles/x.json
          /users
          /users/x.json
        EOM
      end

      it "knife delete -r /cookbooks/x deletes x remotely but not locally" do
        knife("delete -r /cookbooks/x").should_succeed "Deleted /cookbooks/x\n"
        knife("list -Rf /").should_succeed <<~EOM
          /clients
          /clients/chef-validator.json
          /clients/chef-webui.json
          /clients/x.json
          /cookbooks
          /data_bags
          /data_bags/x
          /data_bags/x/y.json
          /environments
          /environments/_default.json
          /environments/x.json
          /nodes
          /nodes/x.json
          /roles
          /roles/x.json
          /users
          /users/admin.json
          /users/x.json
        EOM
        knife("list -Rf --local /").should_succeed everything
      end

      # TODO delete empty data bag (particularly different on local side)
      context "with an empty data bag on both" do
        before do
          data_bag "empty", {}
          directory "data_bags/empty"
        end

        it "knife delete --both /data_bags/empty fails but deletes local version" do
          knife("delete --both /data_bags/empty").should_fail <<~EOM
            ERROR: /data_bags/empty (remote) must be deleted recursively!  Pass -r to knife delete.
            ERROR: /data_bags/empty (local) must be deleted recursively!  Pass -r to knife delete.
          EOM
          knife("list -Rf /").should_succeed <<~EOM
            /clients
            /clients/chef-validator.json
            /clients/chef-webui.json
            /clients/x.json
            /cookbooks
            /cookbooks/x
            /cookbooks/x/metadata.rb
            /data_bags
            /data_bags/empty
            /data_bags/x
            /data_bags/x/y.json
            /environments
            /environments/_default.json
            /environments/x.json
            /nodes
            /nodes/x.json
            /roles
            /roles/x.json
            /users
            /users/admin.json
            /users/x.json
          EOM
          knife("list -Rf --local /").should_succeed <<~EOM
            /clients
            /clients/x.json
            /cookbooks
            /cookbooks/x
            /cookbooks/x/metadata.rb
            /data_bags
            /data_bags/empty
            /data_bags/x
            /data_bags/x/y.json
            /environments
            /environments/_default.json
            /environments/x.json
            /nodes
            /nodes/x.json
            /roles
            /roles/x.json
            /users
            /users/x.json
          EOM
        end
      end

      it "knife delete --both /data_bags/x fails" do
        knife("delete --both /data_bags/x").should_fail <<~EOM
          ERROR: /data_bags/x (remote) must be deleted recursively!  Pass -r to knife delete.
          ERROR: /data_bags/x (local) must be deleted recursively!  Pass -r to knife delete.
        EOM
        knife("list -Rf /").should_succeed server_everything
        knife("list -Rf --local /").should_succeed everything
      end

      it "knife delete --both -r /data_bags/x deletes x" do
        knife("delete --both -r /data_bags/x").should_succeed "Deleted /data_bags/x\n"
        knife("list -Rf /").should_succeed <<~EOM
          /clients
          /clients/chef-validator.json
          /clients/chef-webui.json
          /clients/x.json
          /cookbooks
          /cookbooks/x
          /cookbooks/x/metadata.rb
          /data_bags
          /environments
          /environments/_default.json
          /environments/x.json
          /nodes
          /nodes/x.json
          /roles
          /roles/x.json
          /users
          /users/admin.json
          /users/x.json
        EOM
        knife("list -Rf --local /").should_succeed <<~EOM
          /clients
          /clients/x.json
          /cookbooks
          /cookbooks/x
          /cookbooks/x/metadata.rb
          /data_bags
          /environments
          /environments/_default.json
          /environments/x.json
          /nodes
          /nodes/x.json
          /roles
          /roles/x.json
          /users
          /users/x.json
        EOM
      end

      it "knife delete --both /environments/x.json deletes x" do
        knife("delete --both /environments/x.json").should_succeed "Deleted /environments/x.json\n"
        knife("list -Rf /").should_succeed <<~EOM
          /clients
          /clients/chef-validator.json
          /clients/chef-webui.json
          /clients/x.json
          /cookbooks
          /cookbooks/x
          /cookbooks/x/metadata.rb
          /data_bags
          /data_bags/x
          /data_bags/x/y.json
          /environments
          /environments/_default.json
          /nodes
          /nodes/x.json
          /roles
          /roles/x.json
          /users
          /users/admin.json
          /users/x.json
        EOM
        knife("list -Rf --local /").should_succeed <<~EOM
          /clients
          /clients/x.json
          /cookbooks
          /cookbooks/x
          /cookbooks/x/metadata.rb
          /data_bags
          /data_bags/x
          /data_bags/x/y.json
          /environments
          /environments/_default.json
          /nodes
          /nodes/x.json
          /roles
          /roles/x.json
          /users
          /users/x.json
        EOM
      end

      it "knife delete --both /roles/x.json deletes x" do
        knife("delete --both /roles/x.json").should_succeed "Deleted /roles/x.json\n"
        knife("list -Rf /").should_succeed <<~EOM
          /clients
          /clients/chef-validator.json
          /clients/chef-webui.json
          /clients/x.json
          /cookbooks
          /cookbooks/x
          /cookbooks/x/metadata.rb
          /data_bags
          /data_bags/x
          /data_bags/x/y.json
          /environments
          /environments/_default.json
          /environments/x.json
          /nodes
          /nodes/x.json
          /roles
          /users
          /users/admin.json
          /users/x.json
        EOM
        knife("list -Rf --local /").should_succeed <<~EOM
          /clients
          /clients/x.json
          /cookbooks
          /cookbooks/x
          /cookbooks/x/metadata.rb
          /data_bags
          /data_bags/x
          /data_bags/x/y.json
          /environments
          /environments/_default.json
          /environments/x.json
          /nodes
          /nodes/x.json
          /roles
          /users
          /users/x.json
        EOM
      end

      it "knife delete --both /environments/_default.json fails but still deletes the local copy" do
        knife("delete --both /environments/_default.json").should_fail stderr: "ERROR: /environments/_default.json (remote) cannot be deleted (default environment cannot be modified).\n", stdout: "Deleted /environments/_default.json\n"
        knife("list -Rf /").should_succeed server_everything
        knife("list -Rf --local /").should_succeed <<~EOM
          /clients
          /clients/x.json
          /cookbooks
          /cookbooks/x
          /cookbooks/x/metadata.rb
          /data_bags
          /data_bags/x
          /data_bags/x/y.json
          /environments
          /environments/x.json
          /nodes
          /nodes/x.json
          /roles
          /roles/x.json
          /users
          /users/x.json
        EOM
      end

      it "knife delete --both /environments/nonexistent.json fails" do
        knife("delete --both /environments/nonexistent.json").should_fail "ERROR: /environments/nonexistent.json: No such file or directory\n"
        knife("list -Rf /").should_succeed server_everything
        knife("list -Rf --local /").should_succeed everything
      end

      it "knife delete --both / fails" do
        knife("delete --both /").should_fail <<~EOM
          ERROR: / (remote) cannot be deleted.
          ERROR: / (local) cannot be deleted.
        EOM
        knife("list -Rf /").should_succeed server_everything
        knife("list -Rf --local /").should_succeed everything
      end

      it "knife delete --both -r /* fails" do
        knife("delete --both -r /*").should_fail <<~EOM
          ERROR: / (remote) cannot be deleted.
          ERROR: / (local) cannot be deleted.
          ERROR: /clients (remote) cannot be deleted.
          ERROR: /clients (local) cannot be deleted.
          ERROR: /cookbooks (remote) cannot be deleted.
          ERROR: /cookbooks (local) cannot be deleted.
          ERROR: /data_bags (remote) cannot be deleted.
          ERROR: /data_bags (local) cannot be deleted.
          ERROR: /environments (remote) cannot be deleted.
          ERROR: /environments (local) cannot be deleted.
          ERROR: /nodes (remote) cannot be deleted.
          ERROR: /nodes (local) cannot be deleted.
          ERROR: /roles (remote) cannot be deleted.
          ERROR: /roles (local) cannot be deleted.
          ERROR: /users (remote) cannot be deleted.
          ERROR: /users (local) cannot be deleted.
        EOM
        knife("list -Rf /").should_succeed server_everything
        knife("list -Rf --local /").should_succeed everything
      end
    end

    when_the_repository "has only top-level directories" do
      before do
        directory "clients"
        directory "cookbooks"
        directory "data_bags"
        directory "environments"
        directory "nodes"
        directory "roles"
        directory "users"
      end

      it "knife delete --both /cookbooks/x fails" do
        knife("delete --both /cookbooks/x").should_fail "ERROR: /cookbooks/x (remote) must be deleted recursively!  Pass -r to knife delete.\n"
        knife("list -Rf /").should_succeed server_everything
        knife("list -Rf --local /").should_succeed nothing
      end

      it "knife delete --both -r /cookbooks/x deletes x" do
        knife("delete --both -r /cookbooks/x").should_succeed "Deleted /cookbooks/x\n"
        knife("list -Rf /").should_succeed <<~EOM
          /clients
          /clients/chef-validator.json
          /clients/chef-webui.json
          /clients/x.json
          /cookbooks
          /data_bags
          /data_bags/x
          /data_bags/x/y.json
          /environments
          /environments/_default.json
          /environments/x.json
          /nodes
          /nodes/x.json
          /roles
          /roles/x.json
          /users
          /users/admin.json
          /users/x.json
        EOM
        knife("list -Rf --local /").should_succeed nothing
      end

      it "knife delete --both /data_bags/x fails" do
        knife("delete --both /data_bags/x").should_fail "ERROR: /data_bags/x (remote) must be deleted recursively!  Pass -r to knife delete.\n"
        knife("list -Rf /").should_succeed server_everything
        knife("list -Rf --local /").should_succeed nothing
      end

      it "knife delete --both -r /data_bags/x deletes x" do
        knife("delete --both -r /data_bags/x").should_succeed "Deleted /data_bags/x\n"
        knife("list -Rf /").should_succeed <<~EOM
          /clients
          /clients/chef-validator.json
          /clients/chef-webui.json
          /clients/x.json
          /cookbooks
          /cookbooks/x
          /cookbooks/x/metadata.rb
          /data_bags
          /environments
          /environments/_default.json
          /environments/x.json
          /nodes
          /nodes/x.json
          /roles
          /roles/x.json
          /users
          /users/admin.json
          /users/x.json
        EOM
        knife("list -Rf --local /").should_succeed nothing
      end

      it "knife delete --both /environments/x.json deletes x" do
        knife("delete --both /environments/x.json").should_succeed "Deleted /environments/x.json\n"
        knife("list -Rf /").should_succeed <<~EOM
          /clients
          /clients/chef-validator.json
          /clients/chef-webui.json
          /clients/x.json
          /cookbooks
          /cookbooks/x
          /cookbooks/x/metadata.rb
          /data_bags
          /data_bags/x
          /data_bags/x/y.json
          /environments
          /environments/_default.json
          /nodes
          /nodes/x.json
          /roles
          /roles/x.json
          /users
          /users/admin.json
          /users/x.json
        EOM
        knife("list -Rf --local /").should_succeed nothing
      end

      it "knife delete --both /roles/x.json deletes x" do
        knife("delete --both /roles/x.json").should_succeed "Deleted /roles/x.json\n"
        knife("list -Rf /").should_succeed <<~EOM
          /clients
          /clients/chef-validator.json
          /clients/chef-webui.json
          /clients/x.json
          /cookbooks
          /cookbooks/x
          /cookbooks/x/metadata.rb
          /data_bags
          /data_bags/x
          /data_bags/x/y.json
          /environments
          /environments/_default.json
          /environments/x.json
          /nodes
          /nodes/x.json
          /roles
          /users
          /users/admin.json
          /users/x.json
        EOM
        knife("list -Rf --local /").should_succeed nothing
      end

      it "knife delete --both /environments/_default.json fails" do
        knife("delete --both /environments/_default.json").should_fail "", stderr: "ERROR: /environments/_default.json (remote) cannot be deleted (default environment cannot be modified).\n"
        knife("list -Rf /").should_succeed server_everything
        knife("list -Rf --local /").should_succeed nothing
      end

      it "knife delete --both / fails" do
        knife("delete --both /").should_fail "ERROR: / (remote) cannot be deleted.\nERROR: / (local) cannot be deleted.\n"
        knife("list -Rf /").should_succeed server_everything
        knife("list -Rf --local /").should_succeed nothing
      end

      it "knife delete --both -r /* fails" do
        knife("delete --both -r /*").should_fail <<~EOM
          ERROR: / (remote) cannot be deleted.
          ERROR: / (local) cannot be deleted.
          ERROR: /clients (remote) cannot be deleted.
          ERROR: /clients (local) cannot be deleted.
          ERROR: /cookbooks (remote) cannot be deleted.
          ERROR: /cookbooks (local) cannot be deleted.
          ERROR: /data_bags (remote) cannot be deleted.
          ERROR: /data_bags (local) cannot be deleted.
          ERROR: /environments (remote) cannot be deleted.
          ERROR: /environments (local) cannot be deleted.
          ERROR: /nodes (remote) cannot be deleted.
          ERROR: /nodes (local) cannot be deleted.
          ERROR: /roles (remote) cannot be deleted.
          ERROR: /roles (local) cannot be deleted.
          ERROR: /users (remote) cannot be deleted.
          ERROR: /users (local) cannot be deleted.
        EOM
        knife("list -Rf /").should_succeed server_everything
        knife("list -Rf --local /").should_succeed nothing
      end

      it "knife delete --both /environments/nonexistent.json fails" do
        knife("delete --both /environments/nonexistent.json").should_fail "ERROR: /environments/nonexistent.json: No such file or directory\n"
        knife("list -Rf /").should_succeed server_everything
        knife("list -Rf --local /").should_succeed nothing
      end

      context "and cwd is at the top level" do
        before { cwd "." }
        it "knife delete fails" do
          knife("delete").should_fail "FATAL: You must specify at least one argument. If you want to delete everything in this directory, run \"knife delete --recurse .\"\n", stdout: /USAGE/
          knife("list -Rf /").should_succeed <<~EOM
            clients
            clients/chef-validator.json
            clients/chef-webui.json
            clients/x.json
            cookbooks
            cookbooks/x
            cookbooks/x/metadata.rb
            data_bags
            data_bags/x
            data_bags/x/y.json
            environments
            environments/_default.json
            environments/x.json
            nodes
            nodes/x.json
            roles
            roles/x.json
            users
            users/admin.json
            users/x.json
          EOM
          knife("list -Rf --local /").should_succeed <<~EOM
            clients
            cookbooks
            data_bags
            environments
            nodes
            roles
            users
          EOM
        end
      end
    end
  end

  when_the_chef_server "is empty" do
    when_the_repository "has one of each thing" do
      before do
        file "clients/x.json", {}
        file "cookbooks/x/metadata.rb", ""
        file "data_bags/x/y.json", {}
        file "environments/_default.json", {}
        file "environments/x.json", {}
        file "nodes/x.json", {}
        file "roles/x.json", {}
        file "users/x.json", {}
      end

      it "knife delete --both /cookbooks/x fails" do
        knife("delete --both /cookbooks/x").should_fail "ERROR: /cookbooks/x (local) must be deleted recursively!  Pass -r to knife delete.\n"
        knife("list -Rf /").should_succeed server_nothing
        knife("list -Rf --local /").should_succeed everything
      end

      it "knife delete --both -r /cookbooks/x deletes x" do
        knife("delete --both -r /cookbooks/x").should_succeed "Deleted /cookbooks/x\n"
        knife("list -Rf /").should_succeed server_nothing
        knife("list -Rf --local /").should_succeed <<~EOM
          /clients
          /clients/x.json
          /cookbooks
          /data_bags
          /data_bags/x
          /data_bags/x/y.json
          /environments
          /environments/_default.json
          /environments/x.json
          /nodes
          /nodes/x.json
          /roles
          /roles/x.json
          /users
          /users/x.json
        EOM
      end

      it "knife delete --both /data_bags/x fails" do
        knife("delete --both /data_bags/x").should_fail "ERROR: /data_bags/x (local) must be deleted recursively!  Pass -r to knife delete.\n"
        knife("list -Rf /").should_succeed server_nothing
        knife("list -Rf --local /").should_succeed everything
      end

      it "knife delete --both -r /data_bags/x deletes x" do
        knife("delete --both -r /data_bags/x").should_succeed "Deleted /data_bags/x\n"
        knife("list -Rf /").should_succeed server_nothing
        knife("list -Rf --local /").should_succeed <<~EOM
          /clients
          /clients/x.json
          /cookbooks
          /cookbooks/x
          /cookbooks/x/metadata.rb
          /data_bags
          /environments
          /environments/_default.json
          /environments/x.json
          /nodes
          /nodes/x.json
          /roles
          /roles/x.json
          /users
          /users/x.json
        EOM
      end

      it "knife delete --both /environments/x.json deletes x" do
        knife("delete --both /environments/x.json").should_succeed "Deleted /environments/x.json\n"
        knife("list -Rf /").should_succeed server_nothing
        knife("list -Rf --local /").should_succeed <<~EOM
          /clients
          /clients/x.json
          /cookbooks
          /cookbooks/x
          /cookbooks/x/metadata.rb
          /data_bags
          /data_bags/x
          /data_bags/x/y.json
          /environments
          /environments/_default.json
          /nodes
          /nodes/x.json
          /roles
          /roles/x.json
          /users
          /users/x.json
        EOM
      end

      it "knife delete --both /roles/x.json deletes x" do
        knife("delete --both /roles/x.json").should_succeed "Deleted /roles/x.json\n"
        knife("list -Rf /").should_succeed server_nothing
        knife("list -Rf --local /").should_succeed <<~EOM
          /clients
          /clients/x.json
          /cookbooks
          /cookbooks/x
          /cookbooks/x/metadata.rb
          /data_bags
          /data_bags/x
          /data_bags/x/y.json
          /environments
          /environments/_default.json
          /environments/x.json
          /nodes
          /nodes/x.json
          /roles
          /users
          /users/x.json
        EOM
      end

      it "knife delete --both /environments/_default.json fails but still deletes the local copy" do
        knife("delete --both /environments/_default.json").should_fail stderr: "ERROR: /environments/_default.json (remote) cannot be deleted (default environment cannot be modified).\n", stdout: "Deleted /environments/_default.json\n"
        knife("list -Rf /").should_succeed server_nothing
        knife("list -Rf --local /").should_succeed <<~EOM
          /clients
          /clients/x.json
          /cookbooks
          /cookbooks/x
          /cookbooks/x/metadata.rb
          /data_bags
          /data_bags/x
          /data_bags/x/y.json
          /environments
          /environments/x.json
          /nodes
          /nodes/x.json
          /roles
          /roles/x.json
          /users
          /users/x.json
        EOM
      end

      it "knife delete --both / fails" do
        knife("delete --both /").should_fail "ERROR: / (remote) cannot be deleted.\nERROR: / (local) cannot be deleted.\n"
        knife("list -Rf /").should_succeed server_nothing
        knife("list -Rf --local /").should_succeed everything
      end

      it "knife delete --both -r /* fails" do
        knife("delete --both -r /*").should_fail <<~EOM
          ERROR: / (remote) cannot be deleted.
          ERROR: / (local) cannot be deleted.
          ERROR: /clients (remote) cannot be deleted.
          ERROR: /clients (local) cannot be deleted.
          ERROR: /cookbooks (remote) cannot be deleted.
          ERROR: /cookbooks (local) cannot be deleted.
          ERROR: /data_bags (remote) cannot be deleted.
          ERROR: /data_bags (local) cannot be deleted.
          ERROR: /environments (remote) cannot be deleted.
          ERROR: /environments (local) cannot be deleted.
          ERROR: /nodes (remote) cannot be deleted.
          ERROR: /nodes (local) cannot be deleted.
          ERROR: /roles (remote) cannot be deleted.
          ERROR: /roles (local) cannot be deleted.
          ERROR: /users (remote) cannot be deleted.
          ERROR: /users (local) cannot be deleted.
        EOM
        knife("list -Rf /").should_succeed server_nothing
        knife("list -Rf --local /").should_succeed everything
      end

      it "knife delete --both /environments/nonexistent.json fails" do
        knife("delete --both /environments/nonexistent.json").should_fail "ERROR: /environments/nonexistent.json: No such file or directory\n"
        knife("list -Rf /").should_succeed server_nothing
        knife("list -Rf --local /").should_succeed everything
      end

      context "and cwd is at the top level" do
        before { cwd "." }
        it "knife delete fails" do
          knife("delete").should_fail "FATAL: You must specify at least one argument. If you want to delete everything in this directory, run \"knife delete --recurse .\"\n", stdout: /USAGE/
          knife("list -Rf /").should_succeed <<~EOM
            clients
            clients/chef-validator.json
            clients/chef-webui.json
            cookbooks
            data_bags
            environments
            environments/_default.json
            nodes
            roles
            users
            users/admin.json
          EOM
          knife("list -Rf --local /").should_succeed <<~EOM
            clients
            clients/x.json
            cookbooks
            cookbooks/x
            cookbooks/x/metadata.rb
            data_bags
            data_bags/x
            data_bags/x/y.json
            environments
            environments/_default.json
            environments/x.json
            nodes
            nodes/x.json
            roles
            roles/x.json
            users
            users/x.json
          EOM
        end
      end
    end
  end

  when_the_repository "has a cookbook" do
    before do
      file "cookbooks/x/metadata.rb", 'version "1.0.0"'
      file "cookbooks/x/onlyin1.0.0.rb", "old_text"
    end

    when_the_chef_server "has a later version for the cookbook" do
      before do
        cookbook "x", "1.0.0", { "onlyin1.0.0.rb" => "" }
        cookbook "x", "1.0.1", { "onlyin1.0.1.rb" => "hi" }
      end

      # TODO this seems wrong
      it "knife delete --both -r /cookbooks/x deletes the latest version on the server and the local version" do
        knife("delete --both -r /cookbooks/x").should_succeed "Deleted /cookbooks/x\n"
        knife("raw /cookbooks/x").should_succeed(/1.0.0/)
        knife("list --local /cookbooks").should_succeed ""
      end
    end

    when_the_chef_server "has an earlier version for the cookbook" do
      before do
        cookbook "x", "1.0.0", { "onlyin1.0.0.rb" => "" }
        cookbook "x", "0.9.9", { "onlyin0.9.9.rb" => "hi" }
      end

      it "knife delete --both /cookbooks/x deletes the latest version on the server and the local version" do
        knife("delete --both -r /cookbooks/x").should_succeed "Deleted /cookbooks/x\n"
        knife("raw /cookbooks/x").should_succeed(/0.9.9/)
        knife("list --local /cookbooks").should_succeed ""
      end
    end

    when_the_chef_server "has a later version for the cookbook, and no current version" do
      before { cookbook "x", "1.0.1", { "onlyin1.0.1.rb" => "hi" } }

      it "knife delete --both /cookbooks/x deletes the server and client version of the cookbook" do
        knife("delete --both -r /cookbooks/x").should_succeed "Deleted /cookbooks/x\n"
        knife("raw /cookbooks/x").should_fail(/404/)
        knife("list --local /cookbooks").should_succeed ""
      end
    end

    when_the_chef_server "has an earlier version for the cookbook, and no current version" do
      before { cookbook "x", "0.9.9", { "onlyin0.9.9.rb" => "hi" } }

      it "knife delete --both /cookbooks/x deletes the server and client version of the cookbook" do
        knife("delete --both -r /cookbooks/x").should_succeed "Deleted /cookbooks/x\n"
        knife("raw /cookbooks/x").should_fail(/404/)
        knife("list --local /cookbooks").should_succeed ""
      end
    end
  end

  when_the_repository "is empty" do
    when_the_chef_server "has two versions of a cookbook" do
      before do
        cookbook "x", "2.0.11"
        cookbook "x", "11.0.0"
      end

      it "knife delete deletes the latest version" do
        knife("delete --both -r /cookbooks/x").should_succeed "Deleted /cookbooks/x\n"
        knife("raw /cookbooks/x").should_succeed( /2.0.11/ )
      end
    end
  end

  when_the_chef_server "is in Enterprise mode", single_org: false do
    before do
      organization "foo" do
        container "x", {}
        group "x", {}
        policy "x", "1.2.3", {}
        policy_group "x", { "policies" => { "x" => { "revision_id" => "1.2.3" } } }
      end
    end

    before :each do
      Chef::Config.chef_server_url = URI.join(Chef::Config.chef_server_url, "/organizations/foo")
    end

    it "knife delete /acls/containers/environments.json fails with a reasonable error" do
      knife("delete /acls/containers/environments.json").should_fail "ERROR: /acls/containers/environments.json (remote) ACLs cannot be deleted.\n"
    end

    it "knife delete /containers/x.json succeeds" do
      knife("delete /containers/x.json").should_succeed "Deleted /containers/x.json\n"
      knife("raw /containers/x.json").should_fail(/404/)
    end

    it "knife delete /groups/x.json succeeds" do
      knife("delete /groups/x.json").should_succeed "Deleted /groups/x.json\n"
      knife("raw /groups/x.json").should_fail(/404/)
    end

    it "knife delete /policies/x-1.2.3.json succeeds" do
      knife("raw /policies/x/revisions/1.2.3").should_succeed "{\n  \"name\": \"x\",\n  \"revision_id\": \"1.2.3\",\n  \"run_list\": [\n\n  ],\n  \"cookbook_locks\": {\n\n  }\n}\n"
      knife("delete /policies/x-1.2.3.json").should_succeed "Deleted /policies/x-1.2.3.json\n"
      knife("raw /policies/x/revisions/1.2.3").should_fail(/404/)
    end

    it "knife delete /policy_groups/x.json succeeds" do
      knife("raw /policy_groups/x").should_succeed "{\n  \"uri\": \"http://127.0.0.1:8900/organizations/foo/policy_groups/x\",\n  \"policies\": {\n    \"x\": {\n      \"revision_id\": \"1.2.3\"\n    }\n  }\n}\n"
      knife("delete /policy_groups/x.json").should_succeed "Deleted /policy_groups/x.json\n"
      knife("raw /policy_groups/x").should_fail(/404/)
    end

    it "knife delete /org.json fails with a reasonable error" do
      knife("delete /org.json").should_fail "ERROR: /org.json (remote) cannot be deleted.\n"
    end

    it "knife delete /invitations.json fails with a reasonable error" do
      knife("delete /invitations.json").should_fail "ERROR: /invitations.json (remote) cannot be deleted.\n"
    end

    it "knife delete /members.json fails with a reasonable error" do
      knife("delete /members.json").should_fail "ERROR: /members.json (remote) cannot be deleted.\n"
    end
  end
end
