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
require "support/shared/context/config"
require "chef/knife/list"

describe "knife list", :workstation do
  include IntegrationSupport
  include KnifeSupport

  include_context "default config options"

  when_the_chef_server "is empty" do
    it "knife list / returns all top level directories" do
      knife("list /").should_succeed <<~EOM
        /clients
        /cookbooks
        /data_bags
        /environments
        /nodes
        /roles
        /users
      EOM
    end

    it "knife list -R / returns everything" do
      knife("list -R /").should_succeed <<~EOM
        /:
        clients
        cookbooks
        data_bags
        environments
        nodes
        roles
        users

        /clients:
        chef-validator.json
        chef-webui.json

        /cookbooks:

        /data_bags:

        /environments:
        _default.json

        /nodes:

        /roles:

        /users:
        admin.json
      EOM
    end
  end

  when_the_chef_server "has plenty of stuff in it" do
    before do
      client "client1", {}
      client "client2", {}
      cookbook "cookbook1", "1.0.0"
      cookbook "cookbook2", "1.0.1", { "recipes" => { "default.rb" => "" } }
      data_bag "bag1", { "item1" => {}, "item2" => {} }
      data_bag "bag2", { "item1" => {}, "item2" => {} }
      environment "environment1", {}
      environment "environment2", {}
      node "node1", {}
      node "node2", {}
      policy "policy1", "1.2.3", {}
      policy "policy2", "1.2.3", {}
      policy "policy2", "1.3.5", {}
      role "role1", {}
      role "role2", {}
      user "user1", {}
      user "user2", {}
    end

    it "knife list / returns all top level directories" do
      knife("list /").should_succeed <<~EOM
        /clients
        /cookbooks
        /data_bags
        /environments
        /nodes
        /roles
        /users
      EOM
    end

    it "knife list -R / returns everything" do
      knife("list -R /").should_succeed <<~EOM
        /:
        clients
        cookbooks
        data_bags
        environments
        nodes
        roles
        users

        /clients:
        chef-validator.json
        chef-webui.json
        client1.json
        client2.json

        /cookbooks:
        cookbook1
        cookbook2

        /cookbooks/cookbook1:
        metadata.rb

        /cookbooks/cookbook2:
        metadata.rb
        recipes

        /cookbooks/cookbook2/recipes:
        default.rb

        /data_bags:
        bag1
        bag2

        /data_bags/bag1:
        item1.json
        item2.json

        /data_bags/bag2:
        item1.json
        item2.json

        /environments:
        _default.json
        environment1.json
        environment2.json

        /nodes:
        node1.json
        node2.json

        /roles:
        role1.json
        role2.json

        /users:
        admin.json
        user1.json
        user2.json
      EOM
    end

    it "knife list -R --flat / returns everything" do
      knife("list -R --flat /").should_succeed <<~EOM
        /clients
        /clients/chef-validator.json
        /clients/chef-webui.json
        /clients/client1.json
        /clients/client2.json
        /cookbooks
        /cookbooks/cookbook1
        /cookbooks/cookbook1/metadata.rb
        /cookbooks/cookbook2
        /cookbooks/cookbook2/metadata.rb
        /cookbooks/cookbook2/recipes
        /cookbooks/cookbook2/recipes/default.rb
        /data_bags
        /data_bags/bag1
        /data_bags/bag1/item1.json
        /data_bags/bag1/item2.json
        /data_bags/bag2
        /data_bags/bag2/item1.json
        /data_bags/bag2/item2.json
        /environments
        /environments/_default.json
        /environments/environment1.json
        /environments/environment2.json
        /nodes
        /nodes/node1.json
        /nodes/node2.json
        /roles
        /roles/role1.json
        /roles/role2.json
        /users
        /users/admin.json
        /users/user1.json
        /users/user2.json
      EOM
    end

    it "knife list -Rfp / returns everything" do
      knife("list -Rfp /").should_succeed <<~EOM
        /clients/
        /clients/chef-validator.json
        /clients/chef-webui.json
        /clients/client1.json
        /clients/client2.json
        /cookbooks/
        /cookbooks/cookbook1/
        /cookbooks/cookbook1/metadata.rb
        /cookbooks/cookbook2/
        /cookbooks/cookbook2/metadata.rb
        /cookbooks/cookbook2/recipes/
        /cookbooks/cookbook2/recipes/default.rb
        /data_bags/
        /data_bags/bag1/
        /data_bags/bag1/item1.json
        /data_bags/bag1/item2.json
        /data_bags/bag2/
        /data_bags/bag2/item1.json
        /data_bags/bag2/item2.json
        /environments/
        /environments/_default.json
        /environments/environment1.json
        /environments/environment2.json
        /nodes/
        /nodes/node1.json
        /nodes/node2.json
        /roles/
        /roles/role1.json
        /roles/role2.json
        /users/
        /users/admin.json
        /users/user1.json
        /users/user2.json
      EOM
    end

    it "knife list /cookbooks returns the list of cookbooks" do
      knife("list /cookbooks").should_succeed <<~EOM
        /cookbooks/cookbook1
        /cookbooks/cookbook2
      EOM
    end

    it "knife list /cookbooks/*2/*/*.rb returns the one file" do
      knife("list /cookbooks/*2/*/*.rb").should_succeed "/cookbooks/cookbook2/recipes/default.rb\n"
    end

    it "knife list /**.rb returns all ruby files" do
      knife("list /**.rb").should_succeed <<~EOM
        /cookbooks/cookbook1/metadata.rb
        /cookbooks/cookbook2/metadata.rb
        /cookbooks/cookbook2/recipes/default.rb
      EOM
    end

    it "knife list /cookbooks/**.rb returns all ruby files" do
      knife("list /cookbooks/**.rb").should_succeed <<~EOM
        /cookbooks/cookbook1/metadata.rb
        /cookbooks/cookbook2/metadata.rb
        /cookbooks/cookbook2/recipes/default.rb
      EOM
    end

    it "knife list /**.json returns all json files" do
      knife("list /**.json").should_succeed <<~EOM
        /clients/chef-validator.json
        /clients/chef-webui.json
        /clients/client1.json
        /clients/client2.json
        /data_bags/bag1/item1.json
        /data_bags/bag1/item2.json
        /data_bags/bag2/item1.json
        /data_bags/bag2/item2.json
        /environments/_default.json
        /environments/environment1.json
        /environments/environment2.json
        /nodes/node1.json
        /nodes/node2.json
        /roles/role1.json
        /roles/role2.json
        /users/admin.json
        /users/user1.json
        /users/user2.json
      EOM
    end

    it "knife list /data**.json returns all data bag json files" do
      knife("list /data**.json").should_succeed <<~EOM
        /data_bags/bag1/item1.json
        /data_bags/bag1/item2.json
        /data_bags/bag2/item1.json
        /data_bags/bag2/item2.json
      EOM
    end

    it "knife list /environments/missing_file.json reports missing file" do
      knife("list /environments/missing_file.json").should_fail "ERROR: /environments/missing_file.json: No such file or directory\n"
    end

    context "missing file/directory exact match tests" do
      it "knife list /blarghle reports missing directory" do
        knife("list /blarghle").should_fail "ERROR: /blarghle: No such file or directory\n"
      end
    end

    context "symlink tests" do
      when_the_repository "is empty" do
        context "when cwd is at the top of the repository" do
          before { cwd "." }

          it "knife list -Rfp returns everything" do
            knife("list -Rfp").should_succeed <<~EOM
              clients/
              clients/chef-validator.json
              clients/chef-webui.json
              clients/client1.json
              clients/client2.json
              cookbooks/
              cookbooks/cookbook1/
              cookbooks/cookbook1/metadata.rb
              cookbooks/cookbook2/
              cookbooks/cookbook2/metadata.rb
              cookbooks/cookbook2/recipes/
              cookbooks/cookbook2/recipes/default.rb
              data_bags/
              data_bags/bag1/
              data_bags/bag1/item1.json
              data_bags/bag1/item2.json
              data_bags/bag2/
              data_bags/bag2/item1.json
              data_bags/bag2/item2.json
              environments/
              environments/_default.json
              environments/environment1.json
              environments/environment2.json
              nodes/
              nodes/node1.json
              nodes/node2.json
              roles/
              roles/role1.json
              roles/role2.json
              users/
              users/admin.json
              users/user1.json
              users/user2.json
            EOM
          end
        end
      end

      when_the_repository "has a cookbooks directory" do
        before { directory "cookbooks" }
        context "when cwd is in cookbooks/" do
          before { cwd "cookbooks" }

          it "knife list -Rfp / returns everything" do
            knife("list -Rfp /").should_succeed <<~EOM
              /clients/
              /clients/chef-validator.json
              /clients/chef-webui.json
              /clients/client1.json
              /clients/client2.json
              ./
              cookbook1/
              cookbook1/metadata.rb
              cookbook2/
              cookbook2/metadata.rb
              cookbook2/recipes/
              cookbook2/recipes/default.rb
              /data_bags/
              /data_bags/bag1/
              /data_bags/bag1/item1.json
              /data_bags/bag1/item2.json
              /data_bags/bag2/
              /data_bags/bag2/item1.json
              /data_bags/bag2/item2.json
              /environments/
              /environments/_default.json
              /environments/environment1.json
              /environments/environment2.json
              /nodes/
              /nodes/node1.json
              /nodes/node2.json
              /roles/
              /roles/role1.json
              /roles/role2.json
              /users/
              /users/admin.json
              /users/user1.json
              /users/user2.json
            EOM
          end

          it "knife list -Rfp .. returns everything" do
            knife("list -Rfp ..").should_succeed <<~EOM
              /clients/
              /clients/chef-validator.json
              /clients/chef-webui.json
              /clients/client1.json
              /clients/client2.json
              ./
              cookbook1/
              cookbook1/metadata.rb
              cookbook2/
              cookbook2/metadata.rb
              cookbook2/recipes/
              cookbook2/recipes/default.rb
              /data_bags/
              /data_bags/bag1/
              /data_bags/bag1/item1.json
              /data_bags/bag1/item2.json
              /data_bags/bag2/
              /data_bags/bag2/item1.json
              /data_bags/bag2/item2.json
              /environments/
              /environments/_default.json
              /environments/environment1.json
              /environments/environment2.json
              /nodes/
              /nodes/node1.json
              /nodes/node2.json
              /roles/
              /roles/role1.json
              /roles/role2.json
              /users/
              /users/admin.json
              /users/user1.json
              /users/user2.json
            EOM
          end

          it "knife list -Rfp returns cookbooks" do
            knife("list -Rfp").should_succeed <<~EOM
              cookbook1/
              cookbook1/metadata.rb
              cookbook2/
              cookbook2/metadata.rb
              cookbook2/recipes/
              cookbook2/recipes/default.rb
            EOM
          end
        end
      end

      when_the_repository "has a cookbooks/cookbook2 directory" do
        before { directory "cookbooks/cookbook2" }

        context "when cwd is in cookbooks/cookbook2" do
          before { cwd "cookbooks/cookbook2" }

          it "knife list -Rfp returns cookbooks" do
            knife("list -Rfp").should_succeed <<~EOM
              metadata.rb
              recipes/
              recipes/default.rb
            EOM
          end
        end
      end

      when_the_repository "has a cookbooks directory and a symlinked cookbooks directory", skip: (ChefUtils.windows?) do
        before do
          directory "cookbooks"
          symlink "symlinked", "cookbooks"
        end

        context "when cwd is in cookbooks/" do
          before { cwd "cookbooks" }

          it "knife list -Rfp returns cookbooks" do
            knife("list -Rfp").should_succeed <<~EOM
              cookbook1/
              cookbook1/metadata.rb
              cookbook2/
              cookbook2/metadata.rb
              cookbook2/recipes/
              cookbook2/recipes/default.rb
            EOM
          end
        end

        context "when cwd is in symlinked/" do
          before { cwd "symlinked" }

          it "knife list -Rfp returns cookbooks" do
            knife("list -Rfp").should_succeed <<~EOM
              cookbook1/
              cookbook1/metadata.rb
              cookbook2/
              cookbook2/metadata.rb
              cookbook2/recipes/
              cookbook2/recipes/default.rb
            EOM
          end
        end
      end

      when_the_repository "has a real_cookbooks directory and a cookbooks symlink to it", skip: (ChefUtils.windows?) do
        before do
          directory "real_cookbooks"
          symlink "cookbooks", "real_cookbooks"
        end

        context "when cwd is in real_cookbooks/" do
          before { cwd "real_cookbooks" }

          it "knife list -Rfp returns cookbooks" do
            knife("list -Rfp").should_succeed <<~EOM
              cookbook1/
              cookbook1/metadata.rb
              cookbook2/
              cookbook2/metadata.rb
              cookbook2/recipes/
              cookbook2/recipes/default.rb
            EOM
          end
        end

        context "when cwd is in cookbooks/" do
          before { cwd "cookbooks" }

          it "knife list -Rfp returns cookbooks" do
            knife("list -Rfp").should_succeed <<~EOM
              cookbook1/
              cookbook1/metadata.rb
              cookbook2/
              cookbook2/metadata.rb
              cookbook2/recipes/
              cookbook2/recipes/default.rb
            EOM
          end
        end
      end
    end
  end

  context "--local" do
    when_the_repository "is empty" do
      it "knife list --local / returns nothing" do
        knife("list --local /").should_succeed ""
      end

      it "knife list /roles returns nothing" do
        knife("list --local /roles").should_fail "ERROR: /roles: No such file or directory\n"
      end
    end

    when_the_repository "has a bunch of stuff" do
      before do
        file "clients/client1.json", {}
        file "clients/client2.json", {}

        directory "cookbooks/cookbook1" do
          file "metadata.rb", cb_metadata("cookbook1", "1.0.0")
        end
        directory "cookbooks/cookbook2" do
          file "metadata.rb", cb_metadata("cookbook2", "2.0.0")
          file "recipes/default.rb", ""
        end

        directory "data_bags" do
          directory "bag1" do
            file "item1.json", {}
            file "item2.json", {}
          end
          directory "bag2" do
            file "item1.json", {}
            file "item2.json", {}
          end
        end

        file "environments/environment1.json", {}
        file "environments/environment2.json", {}
        file "nodes/node1.json", {}
        file "nodes/node2.json", {}

        file "roles/role1.json", {}
        file "roles/role2.json", {}
        file "users/user1.json", {}
        file "users/user2.json", {}
      end

      it "knife list -Rfp / returns everything" do
        knife("list -Rp --local --flat /").should_succeed <<~EOM
          /clients/
          /clients/client1.json
          /clients/client2.json
          /cookbooks/
          /cookbooks/cookbook1/
          /cookbooks/cookbook1/metadata.rb
          /cookbooks/cookbook2/
          /cookbooks/cookbook2/metadata.rb
          /cookbooks/cookbook2/recipes/
          /cookbooks/cookbook2/recipes/default.rb
          /data_bags/
          /data_bags/bag1/
          /data_bags/bag1/item1.json
          /data_bags/bag1/item2.json
          /data_bags/bag2/
          /data_bags/bag2/item1.json
          /data_bags/bag2/item2.json
          /environments/
          /environments/environment1.json
          /environments/environment2.json
          /nodes/
          /nodes/node1.json
          /nodes/node2.json
          /roles/
          /roles/role1.json
          /roles/role2.json
          /users/
          /users/user1.json
          /users/user2.json
        EOM
      end

      context "missing file/directory tests" do
        it "knife list --local /blarghle reports missing directory" do
          knife("list --local /blarghle").should_fail "ERROR: /blarghle: No such file or directory\n"
        end

        it "knife list /roles/blarghle reports missing directory" do
          knife("list --local /roles/blarghle").should_fail "ERROR: /roles/blarghle: No such file or directory\n"
        end

        it "knife list /roles/blarghle/blorghle reports missing directory" do
          knife("list --local /roles/blarghle/blorghle").should_fail "ERROR: /roles/blarghle/blorghle: No such file or directory\n"
        end
      end
    end
  end

  when_the_chef_server "is in Enterprise mode", single_org: false do
    before do
      organization "foo"
    end

    before :each do
      Chef::Config.chef_server_url = URI.join(Chef::Config.chef_server_url, "/organizations/foo")
    end

    context "and is empty" do
      it "knife list / returns all top level directories" do
        knife("list /").should_succeed <<~EOM
          /acls
          /clients
          /containers
          /cookbook_artifacts
          /cookbooks
          /data_bags
          /environments
          /groups
          /invitations.json
          /members.json
          /nodes
          /org.json
          /policies
          /policy_groups
          /roles
        EOM
      end

      it "knife list -R / returns everything" do
        knife("list -R /").should_succeed <<~EOM
          /:
          acls
          clients
          containers
          cookbook_artifacts
          cookbooks
          data_bags
          environments
          groups
          invitations.json
          members.json
          nodes
          org.json
          policies
          policy_groups
          roles

          /acls:
          clients
          containers
          cookbook_artifacts
          cookbooks
          data_bags
          environments
          groups
          nodes
          organization.json
          policies
          policy_groups
          roles

          /acls/clients:
          foo-validator.json

          /acls/containers:
          clients.json
          containers.json
          cookbook_artifacts.json
          cookbooks.json
          data.json
          environments.json
          groups.json
          nodes.json
          policies.json
          policy_groups.json
          roles.json
          sandboxes.json

          /acls/cookbook_artifacts:

          /acls/cookbooks:

          /acls/data_bags:

          /acls/environments:
          _default.json

          /acls/groups:
          admins.json
          billing-admins.json
          clients.json
          users.json

          /acls/nodes:

          /acls/policies:

          /acls/policy_groups:

          /acls/roles:

          /clients:
          foo-validator.json

          /containers:
          clients.json
          containers.json
          cookbook_artifacts.json
          cookbooks.json
          data.json
          environments.json
          groups.json
          nodes.json
          policies.json
          policy_groups.json
          roles.json
          sandboxes.json

          /cookbook_artifacts:

          /cookbooks:

          /data_bags:

          /environments:
          _default.json

          /groups:
          admins.json
          billing-admins.json
          clients.json
          users.json

          /nodes:

          /policies:

          /policy_groups:

          /roles:
        EOM
      end
    end

    it "knife list -R / returns everything" do
      knife("list -R /").should_succeed <<~EOM
        /:
        acls
        clients
        containers
        cookbook_artifacts
        cookbooks
        data_bags
        environments
        groups
        invitations.json
        members.json
        nodes
        org.json
        policies
        policy_groups
        roles

        /acls:
        clients
        containers
        cookbook_artifacts
        cookbooks
        data_bags
        environments
        groups
        nodes
        organization.json
        policies
        policy_groups
        roles

        /acls/clients:
        foo-validator.json

        /acls/containers:
        clients.json
        containers.json
        cookbook_artifacts.json
        cookbooks.json
        data.json
        environments.json
        groups.json
        nodes.json
        policies.json
        policy_groups.json
        roles.json
        sandboxes.json

        /acls/cookbook_artifacts:

        /acls/cookbooks:

        /acls/data_bags:

        /acls/environments:
        _default.json

        /acls/groups:
        admins.json
        billing-admins.json
        clients.json
        users.json

        /acls/nodes:

        /acls/policies:

        /acls/policy_groups:

        /acls/roles:

        /clients:
        foo-validator.json

        /containers:
        clients.json
        containers.json
        cookbook_artifacts.json
        cookbooks.json
        data.json
        environments.json
        groups.json
        nodes.json
        policies.json
        policy_groups.json
        roles.json
        sandboxes.json

        /cookbook_artifacts:

        /cookbooks:

        /data_bags:

        /environments:
        _default.json

        /groups:
        admins.json
        billing-admins.json
        clients.json
        users.json

        /nodes:

        /policies:

        /policy_groups:

        /roles:
      EOM
    end

    context "has plenty of stuff in it" do
      before do
        client "client1", {}
        client "client2", {}
        container "container1", {}
        container "container2", {}
        cookbook "cookbook1", "1.0.0"
        cookbook "cookbook2", "1.0.1", { "recipes" => { "default.rb" => "" } }
        cookbook_artifact "cookbook_artifact1", "1x1"
        cookbook_artifact "cookbook_artifact2", "2x2", { "recipes" => { "default.rb" => "" } }
        data_bag "bag1", { "item1" => {}, "item2" => {} }
        data_bag "bag2", { "item1" => {}, "item2" => {} }
        environment "environment1", {}
        environment "environment2", {}
        group "group1", {}
        group "group2", {}
        node "node1", {}
        node "node2", {}
        org_invite "user1"
        org_member "user2"
        policy "policy1", "1.2.3", {}
        policy "policy2", "1.2.3", {}
        policy "policy2", "1.3.5", {}
        policy_group "policy_group1", { "policies" => { "policy1" => { "revision_id" => "1.2.3" } } }
        policy_group "policy_group2", { "policies" => { "policy2" => { "revision_id" => "1.3.5" } } }
        role "role1", {}
        role "role2", {}
        user "user1", {}
        user "user2", {}
      end

      it "knife list -Rfp / returns everything" do
        knife("list -Rfp /").should_succeed <<~EOM
          /acls/
          /acls/clients/
          /acls/clients/client1.json
          /acls/clients/client2.json
          /acls/clients/foo-validator.json
          /acls/containers/
          /acls/containers/clients.json
          /acls/containers/container1.json
          /acls/containers/container2.json
          /acls/containers/containers.json
          /acls/containers/cookbook_artifacts.json
          /acls/containers/cookbooks.json
          /acls/containers/data.json
          /acls/containers/environments.json
          /acls/containers/groups.json
          /acls/containers/nodes.json
          /acls/containers/policies.json
          /acls/containers/policy_groups.json
          /acls/containers/roles.json
          /acls/containers/sandboxes.json
          /acls/cookbook_artifacts/
          /acls/cookbook_artifacts/cookbook_artifact1.json
          /acls/cookbook_artifacts/cookbook_artifact2.json
          /acls/cookbooks/
          /acls/cookbooks/cookbook1.json
          /acls/cookbooks/cookbook2.json
          /acls/data_bags/
          /acls/data_bags/bag1.json
          /acls/data_bags/bag2.json
          /acls/environments/
          /acls/environments/_default.json
          /acls/environments/environment1.json
          /acls/environments/environment2.json
          /acls/groups/
          /acls/groups/admins.json
          /acls/groups/billing-admins.json
          /acls/groups/clients.json
          /acls/groups/group1.json
          /acls/groups/group2.json
          /acls/groups/users.json
          /acls/nodes/
          /acls/nodes/node1.json
          /acls/nodes/node2.json
          /acls/organization.json
          /acls/policies/
          /acls/policies/policy1.json
          /acls/policies/policy2.json
          /acls/policy_groups/
          /acls/policy_groups/policy_group1.json
          /acls/policy_groups/policy_group2.json
          /acls/roles/
          /acls/roles/role1.json
          /acls/roles/role2.json
          /clients/
          /clients/client1.json
          /clients/client2.json
          /clients/foo-validator.json
          /containers/
          /containers/clients.json
          /containers/container1.json
          /containers/container2.json
          /containers/containers.json
          /containers/cookbook_artifacts.json
          /containers/cookbooks.json
          /containers/data.json
          /containers/environments.json
          /containers/groups.json
          /containers/nodes.json
          /containers/policies.json
          /containers/policy_groups.json
          /containers/roles.json
          /containers/sandboxes.json
          /cookbook_artifacts/
          /cookbook_artifacts/cookbook_artifact1-1x1/
          /cookbook_artifacts/cookbook_artifact1-1x1/metadata.rb
          /cookbook_artifacts/cookbook_artifact2-2x2/
          /cookbook_artifacts/cookbook_artifact2-2x2/metadata.rb
          /cookbook_artifacts/cookbook_artifact2-2x2/recipes/
          /cookbook_artifacts/cookbook_artifact2-2x2/recipes/default.rb
          /cookbooks/
          /cookbooks/cookbook1/
          /cookbooks/cookbook1/metadata.rb
          /cookbooks/cookbook2/
          /cookbooks/cookbook2/metadata.rb
          /cookbooks/cookbook2/recipes/
          /cookbooks/cookbook2/recipes/default.rb
          /data_bags/
          /data_bags/bag1/
          /data_bags/bag1/item1.json
          /data_bags/bag1/item2.json
          /data_bags/bag2/
          /data_bags/bag2/item1.json
          /data_bags/bag2/item2.json
          /environments/
          /environments/_default.json
          /environments/environment1.json
          /environments/environment2.json
          /groups/
          /groups/admins.json
          /groups/billing-admins.json
          /groups/clients.json
          /groups/group1.json
          /groups/group2.json
          /groups/users.json
          /invitations.json
          /members.json
          /nodes/
          /nodes/node1.json
          /nodes/node2.json
          /org.json
          /policies/
          /policies/policy1-1.2.3.json
          /policies/policy2-1.2.3.json
          /policies/policy2-1.3.5.json
          /policy_groups/
          /policy_groups/policy_group1.json
          /policy_groups/policy_group2.json
          /roles/
          /roles/role1.json
          /roles/role2.json
        EOM
      end
    end
  end
end
