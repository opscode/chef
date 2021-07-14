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
require "chef/knife/upload"
require "chef/knife/diff"
require "chef/knife/raw"
require "chef/json_compat"

describe "knife upload", :workstation do
  include IntegrationSupport
  include KnifeSupport

  context "without versioned cookbooks" do

    when_the_chef_server "has one of each thing" do

      before do
        client "x", {}
        cookbook "x", "1.0.0"
        data_bag "x", { "y" => {} }
        environment "x", {}
        node "x", {}
        role "x", {}
        user "x", {}
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

        it "knife upload does nothing" do
          knife("upload /").should_succeed ""
          knife("diff --name-status /").should_succeed <<~EOM
            D\t/clients/chef-validator.json
            D\t/clients/chef-webui.json
            D\t/clients/x.json
            D\t/cookbooks/x
            D\t/data_bags/x
            D\t/environments/_default.json
            D\t/environments/x.json
            D\t/nodes/x.json
            D\t/roles/x.json
            D\t/users/admin.json
            D\t/users/x.json
          EOM
        end

        it "knife upload --purge deletes everything" do
          knife("upload --purge /").should_succeed(<<~EOM, stderr: "WARNING: /environments/_default.json cannot be deleted (default environment cannot be modified).\n")
            Deleted extra entry /clients/chef-validator.json (purge is on)
            Deleted extra entry /clients/chef-webui.json (purge is on)
            Deleted extra entry /clients/x.json (purge is on)
            Deleted extra entry /cookbooks/x (purge is on)
            Deleted extra entry /data_bags/x (purge is on)
            Deleted extra entry /environments/x.json (purge is on)
            Deleted extra entry /nodes/x.json (purge is on)
            Deleted extra entry /roles/x.json (purge is on)
            Deleted extra entry /users/admin.json (purge is on)
            Deleted extra entry /users/x.json (purge is on)
          EOM
          knife("diff --name-status /").should_succeed <<~EOM
            D\t/environments/_default.json
          EOM
        end
      end

      when_the_repository "has an identical copy of each thing" do

        before do
          file "clients/chef-validator.json", { "validator" => true, "public_key" => ChefZero::PUBLIC_KEY }
          file "clients/chef-webui.json", { "admin" => true, "public_key" => ChefZero::PUBLIC_KEY }
          file "clients/x.json", { "public_key" => ChefZero::PUBLIC_KEY }
          file "cookbooks/x/metadata.rb", cb_metadata("x", "1.0.0")
          file "data_bags/x/y.json", {}
          file "environments/_default.json", { "description" => "The default Chef environment" }
          file "environments/x.json", {}
          file "nodes/x.json", { "normal" => { "tags" => [] } }
          file "roles/x.json", {}
          file "users/admin.json", { "admin" => true, "public_key" => ChefZero::PUBLIC_KEY }
          file "users/x.json", { "public_key" => ChefZero::PUBLIC_KEY }
        end

        it "knife upload makes no changes" do
          knife("upload /cookbooks/x").should_succeed ""
          knife("diff --name-status /").should_succeed ""
        end

        it "knife upload --purge makes no changes" do
          knife("upload --purge /").should_succeed ""
          knife("diff --name-status /").should_succeed ""
        end

        context "except the role file" do
          before do
            file "roles/x.json", { "description" => "blarghle" }
          end

          it "knife upload changes the role" do
            knife("upload /").should_succeed "Updated /roles/x.json\n"
            knife("diff --name-status /").should_succeed ""
          end
          it "knife upload --no-diff does not change the role" do
            knife("upload --no-diff /").should_succeed ""
            knife("diff --name-status /").should_succeed "M\t/roles/x.json\n"
          end
        end

        context "except the role file is textually different, but not ACTUALLY different" do
          before do
            file "roles/x.json", <<~EOM
              {
                "chef_type": "role",
                "default_attributes":  {
                },
                "env_run_lists": {
                },
                "json_class": "Chef::Role",
                "name": "x",
                "description": "",
                "override_attributes": {
                },
                "run_list": [

                ]
              }
            EOM
          end

          it "knife upload / does not change anything" do
            knife("upload /").should_succeed ""
            knife("diff --name-status /").should_succeed ""
          end
        end

        context "the role is in ruby" do
          before do
            file "roles/x.rb", <<~EOM
              name "x"
              description "blargle"
            EOM
          end

          it "knife upload changes the role" do
            knife("upload /").should_succeed "Updated /roles/x.json\n"
            knife("diff --name-status /").should_succeed ""
          end

          it "knife upload --no-diff does not change the role" do
            knife("upload --no-diff /").should_succeed ""
            knife("diff --name-status /").should_succeed "M\t/roles/x.rb\n"
          end
        end

        context "when cookbook metadata has a self-dependency" do
          before do
            file "cookbooks/x/metadata.rb", "name 'x'; version '1.0.0'; depends 'x'"
          end

          it "fails with RuntimeError" do
            expect { knife("upload /cookbooks") }.to raise_error RuntimeError, /Cookbook depends on itself/
          end
        end

        context "as well as one extra copy of each thing" do
          before do
            file "clients/y.json", { "public_key" => ChefZero::PUBLIC_KEY }
            file "cookbooks/x/blah.rb", ""
            file "cookbooks/y/metadata.rb", cb_metadata("y", "1.0.0")
            file "data_bags/x/z.json", {}
            file "data_bags/y/zz.json", {}
            file "environments/y.json", {}
            file "nodes/y.json", {}
            file "roles/y.json", {}
            file "users/y.json", { "public_key" => ChefZero::PUBLIC_KEY }
          end

          it "knife upload adds the new files" do
            knife("upload /").should_succeed <<~EOM
              Created /clients/y.json
              Updated /cookbooks/x
              Created /cookbooks/y
              Created /data_bags/x/z.json
              Created /data_bags/y
              Created /data_bags/y/zz.json
              Created /environments/y.json
              Created /nodes/y.json
              Created /roles/y.json
              Created /users/y.json
            EOM
            knife("diff --name-status /").should_succeed <<~EOM
              D\t/cookbooks/x/metadata.json
              D\t/cookbooks/y/metadata.json
            EOM
          end

          it "knife upload --no-diff adds the new files" do
            knife("upload --no-diff /").should_succeed <<~EOM
              Created /clients/y.json
              Updated /cookbooks/x
              Created /cookbooks/y
              Created /data_bags/x/z.json
              Created /data_bags/y
              Created /data_bags/y/zz.json
              Created /environments/y.json
              Created /nodes/y.json
              Created /roles/y.json
              Created /users/y.json
            EOM
            knife("diff --name-status /").should_succeed <<~EOM
              D\t/cookbooks/x/metadata.json
              D\t/cookbooks/y/metadata.json
            EOM
          end
        end
      end

      when_the_repository "is empty" do
        it "knife upload does nothing" do
          knife("upload /").should_succeed ""
          knife("diff --name-status /").should_succeed <<~EOM
            D\t/clients
            D\t/cookbooks
            D\t/data_bags
            D\t/environments
            D\t/nodes
            D\t/roles
            D\t/users
          EOM
        end

        it "knife upload --purge deletes nothing" do
          knife("upload --purge /").should_fail <<~EOM
            ERROR: /clients cannot be deleted.
            ERROR: /cookbooks cannot be deleted.
            ERROR: /data_bags cannot be deleted.
            ERROR: /environments cannot be deleted.
            ERROR: /nodes cannot be deleted.
            ERROR: /roles cannot be deleted.
            ERROR: /users cannot be deleted.
          EOM
          knife("diff --name-status /").should_succeed <<~EOM
            D\t/clients
            D\t/cookbooks
            D\t/data_bags
            D\t/environments
            D\t/nodes
            D\t/roles
            D\t/users
          EOM
        end

        context "when current directory is top level" do
          before do
            cwd "."
          end

          it "knife upload with no parameters reports an error" do
            knife("upload").should_fail "FATAL: You must specify at least one argument. If you want to upload everything in this directory, run \"knife upload .\"\n", stdout: /USAGE/
          end
        end
      end
    end

    when_the_chef_server "is empty" do
      when_the_repository "has a data bag item" do

        before do
          file "data_bags/x/y.json", { "foo" => "bar" }
        end

        it "knife upload of the data bag uploads only the values in the data bag item and no other" do
          knife("upload /data_bags/x/y.json").should_succeed <<~EOM
            Created /data_bags/x
            Created /data_bags/x/y.json
          EOM
          knife("diff --name-status /data_bags").should_succeed <<~EOM
          EOM
          expect(Chef::JSONCompat.parse(knife("raw /data/x/y").stdout, create_additions: false).keys.sort).to eq(%w{foo id})
        end

        it "knife upload /data_bags/x /data_bags/x/y.json uploads x once" do
          knife("upload /data_bags/x /data_bags/x/y.json").should_succeed <<~EOM
            Created /data_bags/x
            Created /data_bags/x/y.json
          EOM
        end
      end

      when_the_repository "has a data bag item with keys chef_type and data_bag" do

        before do
          file "data_bags/x/y.json", { "chef_type" => "aaa", "data_bag" => "bbb" }
        end

        it "upload preserves chef_type and data_bag" do
          knife("upload /data_bags/x/y.json").should_succeed <<~EOM
            Created /data_bags/x
            Created /data_bags/x/y.json
          EOM
          knife("diff --name-status /data_bags").should_succeed ""
          result = Chef::JSONCompat.parse(knife("raw /data/x/y").stdout, create_additions: false)
          expect(result.keys.sort).to eq(%w{chef_type data_bag id})
          expect(result["chef_type"]).to eq("aaa")
          expect(result["data_bag"]).to eq("bbb")
        end
      end

      # Test upload of an item when the other end doesn't even have the container
      when_the_repository "has two data bag items" do
        before do
          file "data_bags/x/y.json", {}
          file "data_bags/x/z.json", {}
        end
        it "knife upload of one data bag item itself succeeds" do
          knife("upload /data_bags/x/y.json").should_succeed <<~EOM
            Created /data_bags/x
            Created /data_bags/x/y.json
          EOM
          knife("diff --name-status /data_bags").should_succeed <<~EOM
            A\t/data_bags/x/z.json
          EOM
        end
      end
    end

    when_the_chef_server "has three data bag items" do

      before do
        data_bag "x", { "deleted" => {}, "modified" => {}, "unmodified" => {} }
      end

      when_the_repository "has a modified, unmodified, added and deleted data bag item" do
        before do
          file "data_bags/x/added.json", {}
          file "data_bags/x/modified.json", { "foo" => "bar" }
          file "data_bags/x/unmodified.json", {}
        end

        it "knife upload of the modified file succeeds" do
          knife("upload /data_bags/x/modified.json").should_succeed <<~EOM
            Updated /data_bags/x/modified.json
          EOM
          knife("diff --name-status /data_bags").should_succeed <<~EOM
            D\t/data_bags/x/deleted.json
            A\t/data_bags/x/added.json
          EOM
        end
        it "knife upload of the unmodified file does nothing" do
          knife("upload /data_bags/x/unmodified.json").should_succeed ""
          knife("diff --name-status /data_bags").should_succeed <<~EOM
            D\t/data_bags/x/deleted.json
            M\t/data_bags/x/modified.json
            A\t/data_bags/x/added.json
          EOM
        end
        it "knife upload of the added file succeeds" do
          knife("upload /data_bags/x/added.json").should_succeed <<~EOM
            Created /data_bags/x/added.json
          EOM
          knife("diff --name-status /data_bags").should_succeed <<~EOM
            D\t/data_bags/x/deleted.json
            M\t/data_bags/x/modified.json
          EOM
        end
        it "knife upload of the deleted file does nothing" do
          knife("upload /data_bags/x/deleted.json").should_succeed ""
          knife("diff --name-status /data_bags").should_succeed <<~EOM
            D\t/data_bags/x/deleted.json
            M\t/data_bags/x/modified.json
            A\t/data_bags/x/added.json
          EOM
        end
        it "knife upload --purge of the deleted file deletes it" do
          knife("upload --purge /data_bags/x/deleted.json").should_succeed <<~EOM
            Deleted extra entry /data_bags/x/deleted.json (purge is on)
          EOM
          knife("diff --name-status /data_bags").should_succeed <<~EOM
            M\t/data_bags/x/modified.json
            A\t/data_bags/x/added.json
          EOM
        end
        it "knife upload of the entire data bag uploads everything" do
          knife("upload /data_bags/x").should_succeed <<~EOM
            Created /data_bags/x/added.json
            Updated /data_bags/x/modified.json
          EOM
          knife("diff --name-status /data_bags").should_succeed <<~EOM
            D\t/data_bags/x/deleted.json
          EOM
        end
        it "knife upload --purge of the entire data bag uploads everything" do
          knife("upload --purge /data_bags/x").should_succeed <<~EOM
            Created /data_bags/x/added.json
            Updated /data_bags/x/modified.json
            Deleted extra entry /data_bags/x/deleted.json (purge is on)
          EOM
          knife("diff --name-status /data_bags").should_succeed ""
        end
        context "when cwd is the /data_bags directory" do

          before do
            cwd "data_bags"
          end

          it "knife upload fails" do
            knife("upload").should_fail "FATAL: You must specify at least one argument. If you want to upload everything in this directory, run \"knife upload .\"\n", stdout: /USAGE/
          end

          it "knife upload --purge . uploads everything" do
            knife("upload --purge .").should_succeed <<~EOM
              Created x/added.json
              Updated x/modified.json
              Deleted extra entry x/deleted.json (purge is on)
            EOM
            knife("diff --name-status /data_bags").should_succeed ""
          end
          it "knife upload --purge * uploads everything" do
            knife("upload --purge *").should_succeed <<~EOM
              Created x/added.json
              Updated x/modified.json
              Deleted extra entry x/deleted.json (purge is on)
            EOM
            knife("diff --name-status /data_bags").should_succeed ""
          end
        end
      end
    end

    # Cookbook upload is a funny thing ... direct cookbook upload works, but
    # upload of a file is designed not to work at present.  Make sure that is the
    # case.
    when_the_chef_server "has a cookbook" do
      before do
        cookbook "x", "1.0.0", { "z.rb" => "" }
      end

      when_the_repository "does not have metadata file" do
        before do
          file "cookbooks/x/y.rb", "hi"
        end

        it "raises MetadataNotFound exception" do
          expect { knife("upload /cookbooks/x") }.to raise_error(Chef::Exceptions::MetadataNotFound)
        end
      end

      when_the_repository "does not have valid metadata" do
        before do
          file "cookbooks/x/metadata.rb", cb_metadata(nil, "1.0.0")
        end

        it "raises exception for invalid metadata" do
          expect { knife("upload /cookbooks/x") }.to raise_error(Chef::Exceptions::MetadataNotValid)
        end
      end

      when_the_repository "has a modified, extra and missing file for the cookbook" do
        before do
          file "cookbooks/x/metadata.rb", cb_metadata("x", "1.0.0", "#modified")
          file "cookbooks/x/y.rb", "hi"
        end

        it "knife upload of any individual file fails" do
          knife("upload /cookbooks/x/metadata.rb").should_fail "ERROR: /cookbooks/x/metadata.rb cannot be updated.\n"
          knife("upload /cookbooks/x/y.rb").should_fail "ERROR: /cookbooks/x cannot have a child created under it.\n"
          knife("upload --purge /cookbooks/x/z.rb").should_fail "ERROR: /cookbooks/x/z.rb cannot be deleted.\n"
        end

        # TODO this is a bit of an inconsistency: if we didn't specify --purge,
        # technically we shouldn't have deleted missing files.  But ... cookbooks
        # are a special case.
        it "knife upload of the cookbook itself succeeds" do
          knife("upload /cookbooks/x").should_succeed <<~EOM
            Updated /cookbooks/x
          EOM
          knife("diff --name-status /cookbooks").should_succeed <<~EOM
            D\t/cookbooks/x/metadata.json
          EOM
        end

        it "knife upload --purge of the cookbook itself succeeds" do
          knife("upload /cookbooks/x").should_succeed <<~EOM
            Updated /cookbooks/x
          EOM
          knife("diff --name-status /cookbooks").should_succeed <<~EOM
            D\t/cookbooks/x/metadata.json
          EOM
        end
      end
      when_the_repository "has a missing file for the cookbook" do

        before do
          file "cookbooks/x/metadata.rb", cb_metadata("x", "1.0.0")
        end

        it "knife upload of the cookbook succeeds" do
          knife("upload /cookbooks/x").should_succeed <<~EOM
            Updated /cookbooks/x
          EOM
          knife("diff --name-status /cookbooks").should_succeed <<~EOM
            D\t/cookbooks/x/metadata.json
          EOM
        end
      end
      when_the_repository "has an extra file for the cookbook" do

        before do
          file "cookbooks/x/metadata.rb", cb_metadata("x", "1.0.0")
          file "cookbooks/x/z.rb", ""
          file "cookbooks/x/blah.rb", ""
        end

        it "knife upload of the cookbook succeeds" do
          knife("upload /cookbooks/x").should_succeed <<~EOM
            Updated /cookbooks/x
          EOM
          knife("diff --name-status /cookbooks").should_succeed <<~EOM
            D\t/cookbooks/x/metadata.json
          EOM
        end
      end

      when_the_repository "has a different file in the cookbook" do
        before do
          file "cookbooks/x/metadata.rb", cb_metadata("x", "1.0.0")
        end

        it "knife upload --freeze freezes the cookbook" do
          knife("upload --freeze /cookbooks/x").should_succeed <<~EOM
            Updated /cookbooks/x
          EOM
          # Modify a file and attempt to upload
          file "cookbooks/x/metadata.rb", 'name "x"; version "1.0.0"#different'
          knife("upload /cookbooks/x").should_fail "ERROR: /cookbooks failed to write: Cookbook x is frozen\n"
        end
      end
    end

    when_the_chef_server "has a frozen cookbook" do
      before do
        cookbook "frozencook", "1.0.0", {}, frozen: true
      end

      when_the_repository "has an update to said cookbook" do

        before do
          file "cookbooks/frozencook/metadata.rb", cb_metadata("frozencook", "1.0.0", "# This is different")
        end

        it "knife upload fails to upload the frozen cookbook" do
          knife("upload /cookbooks/frozencook").should_fail "ERROR: /cookbooks failed to write: Cookbook frozencook is frozen\n"
        end
        it "knife upload --force uploads the frozen cookbook" do
          knife("upload --force /cookbooks/frozencook").should_succeed <<~EOM
            Updated /cookbooks/frozencook
          EOM
        end
      end
    end

    when_the_repository "has a cookbook" do
      before do
        file "cookbooks/x/metadata.rb", cb_metadata("x", "1.0.0")
        file "cookbooks/x/metadata.json", { name: "x", version: "1.0.0" }
        file "cookbooks/x/onlyin1.0.0.rb", "old_text"
      end

      when_the_chef_server "has a later version for the cookbook" do
        before do
          cookbook "x", "1.0.0", { "onlyin1.0.0.rb" => "" }
          cookbook "x", "1.0.1", { "onlyin1.0.1.rb" => "hi" }
        end

        it "knife upload /cookbooks/x uploads the local version" do
          knife("diff --name-status /cookbooks").should_succeed <<~EOM
            M\t/cookbooks/x/metadata.rb
            D\t/cookbooks/x/onlyin1.0.1.rb
            A\t/cookbooks/x/metadata.json
            A\t/cookbooks/x/onlyin1.0.0.rb
          EOM
          knife("upload --purge /cookbooks/x").should_succeed <<~EOM
            Updated /cookbooks/x
          EOM
          knife("diff --name-status /cookbooks").should_succeed <<~EOM
            M\t/cookbooks/x/metadata.rb
            D\t/cookbooks/x/onlyin1.0.1.rb
            A\t/cookbooks/x/metadata.json
            A\t/cookbooks/x/onlyin1.0.0.rb
          EOM
        end
      end
    end

    when_the_repository "has a cookbook" do
      before do
        file "cookbooks/x/metadata.rb", cb_metadata("x", "1.0.0")
        file "cookbooks/x/onlyin1.0.0.rb", "old_text"
      end

      when_the_chef_server "has a later version for the cookbook" do
        before do
          cookbook "x", "1.0.0", { "onlyin1.0.0.rb" => "" }
          cookbook "x", "1.0.1", { "onlyin1.0.1.rb" => "hi" }
        end

        it "knife upload /cookbooks/x uploads the local version and generates metadata.json from metadata.rb and uploads it." do
          knife("diff --name-status /cookbooks").should_succeed <<~EOM
            M\t/cookbooks/x/metadata.rb
            D\t/cookbooks/x/onlyin1.0.1.rb
            A\t/cookbooks/x/onlyin1.0.0.rb
          EOM
          knife("upload --purge /cookbooks/x").should_succeed <<~EOM
            Updated /cookbooks/x
          EOM
          knife("diff --name-status /cookbooks").should_succeed <<~EOM
            M\t/cookbooks/x/metadata.rb
            D\t/cookbooks/x/onlyin1.0.1.rb
            A\t/cookbooks/x/onlyin1.0.0.rb
          EOM
        end
      end

      when_the_chef_server "has an earlier version for the cookbook" do
        before do
          cookbook "x", "1.0.0", { "onlyin1.0.0.rb" => "" }
          cookbook "x", "0.9.9", { "onlyin0.9.9.rb" => "hi" }
        end

        it "knife upload /cookbooks/x uploads the local version generates metadata.json and uploads it." do
          knife("upload --purge /cookbooks/x").should_succeed <<~EOM
            Updated /cookbooks/x
          EOM
          knife("diff --name-status /cookbooks").should_succeed <<~EOM
            D\t/cookbooks/x/metadata.json
          EOM
        end
      end

      when_the_chef_server "has a later version for the cookbook, and no current version" do
        before do
          cookbook "x", "1.0.1", { "onlyin1.0.1.rb" => "hi" }
        end

        it "knife upload /cookbooks/x uploads the local version and generates metadata.json before upload and uploads it." do
          knife("diff --name-status /cookbooks").should_succeed <<~EOM
            M\t/cookbooks/x/metadata.rb
            D\t/cookbooks/x/onlyin1.0.1.rb
            A\t/cookbooks/x/onlyin1.0.0.rb
          EOM
          knife("upload --purge /cookbooks/x").should_succeed <<~EOM
            Updated /cookbooks/x
          EOM
          knife("diff --name-status /cookbooks").should_succeed <<~EOM
            M\t/cookbooks/x/metadata.rb
            D\t/cookbooks/x/onlyin1.0.1.rb
            A\t/cookbooks/x/onlyin1.0.0.rb
          EOM
        end
      end

      when_the_chef_server "has an earlier version for the cookbook, and no current version" do
        before do
          cookbook "x", "0.9.9", { "onlyin0.9.9.rb" => "hi" }
        end

        it "knife upload /cookbooks/x uploads the new version" do
          knife("upload --purge /cookbooks/x").should_succeed <<~EOM
            Updated /cookbooks/x
          EOM
          knife("diff --name-status /cookbooks").should_succeed <<~EOM
            D\t/cookbooks/x/metadata.json
          EOM
        end
      end
    end

    when_the_chef_server "has an environment" do
      before do
        environment "x", {}
      end

      when_the_repository "has an environment with bad JSON" do
        before do
          file "environments/x.json", "{"
        end

        it "knife upload tries and fails" do
          error1 = <<~EOH
            WARN: Parse error reading #{path_to("environments/x.json")} as JSON: parse error: premature EOF
                                                   {
                                 (right here) ------^

            ERROR: /environments/x.json failed to write: Parse error reading JSON: parse error: premature EOF
                                                          {
                                        (right here) ------^
          EOH

          warn = <<~EOH
            WARN: Parse error reading #{path_to("environments/x.json")} as JSON: parse error: premature EOF
                                                   {
                                 (right here) ------^

          EOH
          knife("upload /environments/x.json").should_fail(error1)
          knife("diff --name-status /environments/x.json").should_succeed("M\t/environments/x.json\n", stderr: warn)
        end
      end

      when_the_repository "has the same environment with the wrong name in the file" do
        before do
          file "environments/x.json", { "name" => "y" }
        end
        it "knife upload fails" do
          knife("upload /environments/x.json").should_fail "ERROR: /environments/x.json failed to write: Name must be 'x' (is 'y')\n"
          knife("diff --name-status /environments/x.json").should_succeed "M\t/environments/x.json\n"
        end
      end

      when_the_repository "has the same environment with no name in the file" do
        before do
          file "environments/x.json", { "description" => "hi" }
        end
        it "knife upload succeeds" do
          knife("upload /environments/x.json").should_succeed "Updated /environments/x.json\n"
          knife("diff --name-status /environments/x.json").should_succeed ""
        end
      end
    end

    when_the_chef_server "is empty" do

      when_the_repository "has an environment with the wrong name in the file" do
        before do
          file "environments/x.json", { "name" => "y" }
        end
        it "knife upload fails" do
          knife("upload /environments/x.json").should_fail "ERROR: /environments failed to create_child: Error creating 'x.json': Name must be 'x' (is 'y')\n"
          knife("diff --name-status /environments/x.json").should_succeed "A\t/environments/x.json\n"
        end
      end

      when_the_repository "has an environment with no name in the file" do

        before do
          file "environments/x.json", { "description" => "hi" }
        end
        it "knife upload succeeds" do
          knife("upload /environments/x.json").should_succeed "Created /environments/x.json\n"
          knife("diff --name-status /environments/x.json").should_succeed ""
        end
      end

      when_the_repository "has a data bag with no id in the file" do
        before do
          file "data_bags/bag/x.json", { "foo" => "bar" }
        end
        it "knife upload succeeds" do
          knife("upload /data_bags/bag/x.json").should_succeed "Created /data_bags/bag\nCreated /data_bags/bag/x.json\n"
          knife("diff --name-status /data_bags/bag/x.json").should_succeed ""
        end
      end
    end
    when_the_chef_server "is empty" do
      when_the_repository "has a cookbook with an invalid chef_version constraint in it" do
        before do
          file "cookbooks/x/metadata.rb", cb_metadata("x", "1.0.0", "\nchef_version '~> 999.0'")
        end
        it "knife upload succeeds" do
          knife("upload /cookbooks/x").should_succeed <<~EOM
            Created /cookbooks/x
          EOM
          knife("diff --name-status /cookbooks").should_succeed <<~EOM
            D\t/cookbooks/x/metadata.json
          EOM
        end
      end
    end
  end # without versioned cookbooks

  context "with versioned cookbooks" do
    before { Chef::Config[:versioned_cookbooks] = true }

    when_the_chef_server "has one of each thing" do

      before do
        client "x", {}
        cookbook "x", "1.0.0"
        data_bag "x", { "y" => {} }
        environment "x", {}
        node "x", {}
        role "x", {}
        user "x", {}
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

        it "knife upload does nothing" do
          knife("upload /").should_succeed ""
          knife("diff --name-status /").should_succeed <<~EOM
            D\t/clients/chef-validator.json
            D\t/clients/chef-webui.json
            D\t/clients/x.json
            D\t/cookbooks/x-1.0.0
            D\t/data_bags/x
            D\t/environments/_default.json
            D\t/environments/x.json
            D\t/nodes/x.json
            D\t/roles/x.json
            D\t/users/admin.json
            D\t/users/x.json
          EOM
        end

        it "knife upload --purge deletes everything" do
          knife("upload --purge /").should_succeed(<<~EOM, stderr: "WARNING: /environments/_default.json cannot be deleted (default environment cannot be modified).\n")
            Deleted extra entry /clients/chef-validator.json (purge is on)
            Deleted extra entry /clients/chef-webui.json (purge is on)
            Deleted extra entry /clients/x.json (purge is on)
            Deleted extra entry /cookbooks/x-1.0.0 (purge is on)
            Deleted extra entry /data_bags/x (purge is on)
            Deleted extra entry /environments/x.json (purge is on)
            Deleted extra entry /nodes/x.json (purge is on)
            Deleted extra entry /roles/x.json (purge is on)
            Deleted extra entry /users/admin.json (purge is on)
            Deleted extra entry /users/x.json (purge is on)
          EOM
          knife("diff --name-status /").should_succeed <<~EOM
            D\t/environments/_default.json
          EOM
        end
      end

      when_the_repository "has an identical copy of each thing" do
        before do
          file "clients/chef-validator.json", { "validator" => true, "public_key" => ChefZero::PUBLIC_KEY }
          file "clients/chef-webui.json", { "admin" => true, "public_key" => ChefZero::PUBLIC_KEY }
          file "clients/x.json", { "public_key" => ChefZero::PUBLIC_KEY }
          file "cookbooks/x-1.0.0/metadata.rb", cb_metadata("x", "1.0.0")
          file "data_bags/x/y.json", {}
          file "environments/_default.json", { "description" => "The default Chef environment" }
          file "environments/x.json", {}
          file "nodes/x.json", { "normal" => { "tags" => [] } }
          file "roles/x.json", {}
          file "users/admin.json", { "admin" => true, "public_key" => ChefZero::PUBLIC_KEY }
          file "users/x.json", { "public_key" => ChefZero::PUBLIC_KEY }
        end

        it "knife upload makes no changes" do
          knife("upload /cookbooks/x-1.0.0").should_succeed ""
          knife("diff --name-status /").should_succeed ""
        end

        it "knife upload --purge makes no changes" do
          knife("upload --purge /").should_succeed ""
          knife("diff --name-status /").should_succeed ""
        end

        context "except the role file" do
          before do
            file "roles/x.json", { "description" => "blarghle" }
          end

          it "knife upload changes the role" do
            knife("upload /").should_succeed "Updated /roles/x.json\n"
            knife("diff --name-status /").should_succeed ""
          end
        end

        context "except the role file is textually different, but not ACTUALLY different" do

          before do
            file "roles/x.json", <<~EOM
              {
                "chef_type": "role",
                "default_attributes":  {
                },
                "env_run_lists": {
                },
                "json_class": "Chef::Role",
                "name": "x",
                "description": "",
                "override_attributes": {
                },
                "run_list": [

                ]
              }
            EOM
          end

          it "knife upload / does not change anything" do
            knife("upload /").should_succeed ""
            knife("diff --name-status /").should_succeed ""
          end
        end

        context "as well as one extra copy of each thing" do
          before do
            file "clients/y.json", { "public_key" => ChefZero::PUBLIC_KEY }
            file "cookbooks/x-1.0.0/blah.rb", ""
            file "cookbooks/x-2.0.0/metadata.rb", cb_metadata("x", "2.0.0")
            file "cookbooks/y-1.0.0/metadata.rb", cb_metadata("y", "1.0.0")
            file "data_bags/x/z.json", {}
            file "data_bags/y/zz.json", {}
            file "environments/y.json", {}
            file "nodes/y.json", {}
            file "roles/y.json", {}
            file "users/y.json", { "public_key" => ChefZero::PUBLIC_KEY }
          end

          it "knife upload adds the new files" do
            knife("upload /").should_succeed <<~EOM
              Created /clients/y.json
              Updated /cookbooks/x-1.0.0
              Created /cookbooks/x-2.0.0
              Created /cookbooks/y-1.0.0
              Created /data_bags/x/z.json
              Created /data_bags/y
              Created /data_bags/y/zz.json
              Created /environments/y.json
              Created /nodes/y.json
              Created /roles/y.json
              Created /users/y.json
            EOM
            knife("diff --name-status /").should_succeed ""
          end
        end
      end

      when_the_repository "is empty" do
        it "knife upload does nothing" do
          knife("upload /").should_succeed ""
          knife("diff --name-status /").should_succeed <<~EOM
            D\t/clients
            D\t/cookbooks
            D\t/data_bags
            D\t/environments
            D\t/nodes
            D\t/roles
            D\t/users
          EOM
        end

        it "knife upload --purge deletes nothing" do
          knife("upload --purge /").should_fail <<~EOM
            ERROR: /clients cannot be deleted.
            ERROR: /cookbooks cannot be deleted.
            ERROR: /data_bags cannot be deleted.
            ERROR: /environments cannot be deleted.
            ERROR: /nodes cannot be deleted.
            ERROR: /roles cannot be deleted.
            ERROR: /users cannot be deleted.
          EOM
          knife("diff --name-status /").should_succeed <<~EOM
            D\t/clients
            D\t/cookbooks
            D\t/data_bags
            D\t/environments
            D\t/nodes
            D\t/roles
            D\t/users
          EOM
        end

        context "when current directory is top level" do
          before do
            cwd "."
          end
          it "knife upload with no parameters reports an error" do
            knife("upload").should_fail "FATAL: You must specify at least one argument. If you want to upload everything in this directory, run \"knife upload .\"\n", stdout: /USAGE/
          end
        end
      end
    end

    # Test upload of an item when the other end doesn't even have the container
    when_the_chef_server "is empty" do
      when_the_repository "has two data bag items" do
        before do
          file "data_bags/x/y.json", {}
          file "data_bags/x/z.json", {}
        end

        it "knife upload of one data bag item itself succeeds" do
          knife("upload /data_bags/x/y.json").should_succeed <<~EOM
            Created /data_bags/x
            Created /data_bags/x/y.json
          EOM
          knife("diff --name-status /data_bags").should_succeed <<~EOM
            A\t/data_bags/x/z.json
          EOM
        end
      end
    end

    when_the_chef_server "has three data bag items" do
      before do
        data_bag "x", { "deleted" => {}, "modified" => {}, "unmodified" => {} }
      end
      when_the_repository "has a modified, unmodified, added and deleted data bag item" do
        before do
          file "data_bags/x/added.json", {}
          file "data_bags/x/modified.json", { "foo" => "bar" }
          file "data_bags/x/unmodified.json", {}
        end

        it "knife upload of the modified file succeeds" do
          knife("upload /data_bags/x/modified.json").should_succeed <<~EOM
            Updated /data_bags/x/modified.json
          EOM
          knife("diff --name-status /data_bags").should_succeed <<~EOM
            D\t/data_bags/x/deleted.json
            A\t/data_bags/x/added.json
          EOM
        end
        it "knife upload of the unmodified file does nothing" do
          knife("upload /data_bags/x/unmodified.json").should_succeed ""
          knife("diff --name-status /data_bags").should_succeed <<~EOM
            D\t/data_bags/x/deleted.json
            M\t/data_bags/x/modified.json
            A\t/data_bags/x/added.json
          EOM
        end
        it "knife upload of the added file succeeds" do
          knife("upload /data_bags/x/added.json").should_succeed <<~EOM
            Created /data_bags/x/added.json
          EOM
          knife("diff --name-status /data_bags").should_succeed <<~EOM
            D\t/data_bags/x/deleted.json
            M\t/data_bags/x/modified.json
          EOM
        end
        it "knife upload of the deleted file does nothing" do
          knife("upload /data_bags/x/deleted.json").should_succeed ""
          knife("diff --name-status /data_bags").should_succeed <<~EOM
            D\t/data_bags/x/deleted.json
            M\t/data_bags/x/modified.json
            A\t/data_bags/x/added.json
          EOM
        end
        it "knife upload --purge of the deleted file deletes it" do
          knife("upload --purge /data_bags/x/deleted.json").should_succeed <<~EOM
            Deleted extra entry /data_bags/x/deleted.json (purge is on)
          EOM
          knife("diff --name-status /data_bags").should_succeed <<~EOM
            M\t/data_bags/x/modified.json
            A\t/data_bags/x/added.json
          EOM
        end
        it "knife upload of the entire data bag uploads everything" do
          knife("upload /data_bags/x").should_succeed <<~EOM
            Created /data_bags/x/added.json
            Updated /data_bags/x/modified.json
          EOM
          knife("diff --name-status /data_bags").should_succeed <<~EOM
            D\t/data_bags/x/deleted.json
          EOM
        end
        it "knife upload --purge of the entire data bag uploads everything" do
          knife("upload --purge /data_bags/x").should_succeed <<~EOM
            Created /data_bags/x/added.json
            Updated /data_bags/x/modified.json
            Deleted extra entry /data_bags/x/deleted.json (purge is on)
          EOM
          knife("diff --name-status /data_bags").should_succeed ""
        end
        context "when cwd is the /data_bags directory" do
          before do
            cwd "data_bags"
          end
          it "knife upload fails" do
            knife("upload").should_fail "FATAL: You must specify at least one argument. If you want to upload everything in this directory, run \"knife upload .\"\n", stdout: /USAGE/
          end
          it "knife upload --purge . uploads everything" do
            knife("upload --purge .").should_succeed <<~EOM
              Created x/added.json
              Updated x/modified.json
              Deleted extra entry x/deleted.json (purge is on)
            EOM
            knife("diff --name-status /data_bags").should_succeed ""
          end
          it "knife upload --purge * uploads everything" do
            knife("upload --purge *").should_succeed <<~EOM
              Created x/added.json
              Updated x/modified.json
              Deleted extra entry x/deleted.json (purge is on)
            EOM
            knife("diff --name-status /data_bags").should_succeed ""
          end
        end
      end
    end

    # Cookbook upload is a funny thing ... direct cookbook upload works, but
    # upload of a file is designed not to work at present.  Make sure that is the
    # case.
    when_the_chef_server "has a cookbook" do
      before do
        cookbook "x", "1.0.0", { "z.rb" => "" }
      end

      when_the_repository "has a modified, extra and missing file for the cookbook" do
        before do
          file "cookbooks/x-1.0.0/metadata.rb", cb_metadata("x", "1.0.0", "#modified")
          file "cookbooks/x-1.0.0/y.rb", "hi"
        end

        it "knife upload of any individual file fails" do
          knife("upload /cookbooks/x-1.0.0/metadata.rb").should_fail "ERROR: /cookbooks/x-1.0.0/metadata.rb cannot be updated.\n"
          knife("upload /cookbooks/x-1.0.0/y.rb").should_fail "ERROR: /cookbooks/x-1.0.0 cannot have a child created under it.\n"
          knife("upload --purge /cookbooks/x-1.0.0/z.rb").should_fail "ERROR: /cookbooks/x-1.0.0/z.rb cannot be deleted.\n"
        end

        # TODO this is a bit of an inconsistency: if we didn't specify --purge,
        # technically we shouldn't have deleted missing files.  But ... cookbooks
        # are a special case.
        it "knife upload of the cookbook itself succeeds" do
          knife("upload /cookbooks/x-1.0.0").should_succeed <<~EOM
            Updated /cookbooks/x-1.0.0
          EOM
          knife("diff --name-status /cookbooks").should_succeed ""
        end

        it "knife upload --purge of the cookbook itself succeeds" do
          knife("upload /cookbooks/x-1.0.0").should_succeed <<~EOM
            Updated /cookbooks/x-1.0.0
          EOM
          knife("diff --name-status /cookbooks").should_succeed ""
        end
      end

      when_the_repository "has a missing file for the cookbook" do
        before do
          file "cookbooks/x-1.0.0/metadata.rb", cb_metadata("x", "1.0.0")
        end

        it "knife upload of the cookbook succeeds" do
          knife("upload /cookbooks/x-1.0.0").should_succeed <<~EOM
            Updated /cookbooks/x-1.0.0
          EOM
          knife("diff --name-status /cookbooks").should_succeed ""
        end
      end

      when_the_repository "has an extra file for the cookbook" do
        before do
          file "cookbooks/x-1.0.0/metadata.rb", cb_metadata("x", "1.0.0")
          file "cookbooks/x-1.0.0/z.rb", ""
          file "cookbooks/x-1.0.0/blah.rb", ""
        end

        it "knife upload of the cookbook succeeds" do
          knife("upload /cookbooks/x-1.0.0").should_succeed <<~EOM
            Updated /cookbooks/x-1.0.0
          EOM
          knife("diff --name-status /cookbooks").should_succeed ""
        end
      end
    end

    when_the_repository "has a cookbook" do
      before do
        file "cookbooks/x-1.0.0/metadata.rb", cb_metadata("x", "1.0.0")
        file "cookbooks/x-1.0.0/onlyin1.0.0.rb", "old_text"
      end

      when_the_chef_server "has a later version for the cookbook" do
        before do
          cookbook "x", "1.0.0", { "onlyin1.0.0.rb" => "" }
          cookbook "x", "1.0.1", { "onlyin1.0.1.rb" => "hi" }
        end

        it "knife upload /cookbooks uploads the local version" do
          knife("diff --name-status /cookbooks").should_succeed <<~EOM
            M\t/cookbooks/x-1.0.0/onlyin1.0.0.rb
            D\t/cookbooks/x-1.0.1
          EOM
          knife("upload --purge /cookbooks").should_succeed <<~EOM
            Updated /cookbooks/x-1.0.0
            Deleted extra entry /cookbooks/x-1.0.1 (purge is on)
          EOM
          knife("diff --name-status /cookbooks").should_succeed ""
        end
      end

      when_the_chef_server "has an earlier version for the cookbook" do
        before do
          cookbook "x", "1.0.0", { "onlyin1.0.0.rb" => "" }
          cookbook "x", "0.9.9", { "onlyin0.9.9.rb" => "hi" }
        end
        it "knife upload /cookbooks uploads the local version" do
          knife("upload --purge /cookbooks").should_succeed <<~EOM
            Updated /cookbooks/x-1.0.0
            Deleted extra entry /cookbooks/x-0.9.9 (purge is on)
          EOM
          knife("diff --name-status /cookbooks").should_succeed ""
        end
      end

      when_the_chef_server "has a later version for the cookbook, and no current version" do
        before do
          cookbook "x", "1.0.1", { "onlyin1.0.1.rb" => "hi" }
        end

        it "knife upload /cookbooks/x uploads the local version" do
          knife("diff --name-status /cookbooks").should_succeed <<~EOM
            D\t/cookbooks/x-1.0.1
            A\t/cookbooks/x-1.0.0
          EOM
          knife("upload --purge /cookbooks").should_succeed <<~EOM
            Created /cookbooks/x-1.0.0
            Deleted extra entry /cookbooks/x-1.0.1 (purge is on)
          EOM
          knife("diff --name-status /cookbooks").should_succeed ""
        end
      end

      when_the_chef_server "has an earlier version for the cookbook, and no current version" do
        before do
          cookbook "x", "0.9.9", { "onlyin0.9.9.rb" => "hi" }
        end

        it "knife upload /cookbooks/x uploads the new version" do
          knife("upload --purge /cookbooks").should_succeed <<~EOM
            Created /cookbooks/x-1.0.0
            Deleted extra entry /cookbooks/x-0.9.9 (purge is on)
          EOM
          knife("diff --name-status /cookbooks").should_succeed ""
        end
      end
    end

    when_the_chef_server "has an environment" do
      before do
        environment "x", {}
      end

      when_the_repository "has the same environment with the wrong name in the file" do
        before do
          file "environments/x.json", { "name" => "y" }
        end
        it "knife upload fails" do
          knife("upload /environments/x.json").should_fail "ERROR: /environments/x.json failed to write: Name must be 'x' (is 'y')\n"
          knife("diff --name-status /environments/x.json").should_succeed "M\t/environments/x.json\n"
        end
      end

      when_the_repository "has the same environment with no name in the file" do
        before do
          file "environments/x.json", { "description" => "hi" }
        end
        it "knife upload succeeds" do
          knife("upload /environments/x.json").should_succeed "Updated /environments/x.json\n"
          knife("diff --name-status /environments/x.json").should_succeed ""
        end
      end
    end

    when_the_chef_server "is empty" do

      when_the_repository "has an environment with the wrong name in the file" do
        before do
          file "environments/x.json", { "name" => "y" }
        end
        it "knife upload fails" do
          knife("upload /environments/x.json").should_fail "ERROR: /environments failed to create_child: Error creating 'x.json': Name must be 'x' (is 'y')\n"
          knife("diff --name-status /environments/x.json").should_succeed "A\t/environments/x.json\n"
        end
      end

      when_the_repository "has an environment with no name in the file" do
        before do
          file "environments/x.json", { "description" => "hi" }
        end
        it "knife upload succeeds" do
          knife("upload /environments/x.json").should_succeed "Created /environments/x.json\n"
          knife("diff --name-status /environments/x.json").should_succeed ""
        end
      end

      when_the_repository "has a data bag with no id in the file" do
        before do
          file "data_bags/bag/x.json", { "foo" => "bar" }
        end
        it "knife upload succeeds" do
          knife("upload /data_bags/bag/x.json").should_succeed "Created /data_bags/bag\nCreated /data_bags/bag/x.json\n"
          knife("diff --name-status /data_bags/bag/x.json").should_succeed ""
        end
      end
    end

    when_the_chef_server "is empty" do
      when_the_repository "has a cookbook with an invalid chef_version constraint in it" do
        before do
          file "cookbooks/x-1.0.0/metadata.rb", cb_metadata("x", "1.0.0", "\nchef_version '~> 999.0'")
        end
        it "knife upload succeeds" do
          knife("upload /cookbooks/x-1.0.0").should_succeed <<~EOM
            Created /cookbooks/x-1.0.0
          EOM
          knife("diff --name-status /cookbooks").should_succeed ""
        end
      end
    end
  end # with versioned cookbooks

  when_the_chef_server "has a user" do
    before do
      user "x", {}
    end

    when_the_repository "has the same user with json_class in it" do
      before do
        file "users/x.json", { "admin" => true, "json_class" => "Chef::WebUIUser" }
      end
      it "knife upload /users/x.json succeeds" do
        knife("upload /users/x.json").should_succeed "Updated /users/x.json\n"
      end
    end
  end

  when_the_chef_server "is in Enterprise mode", single_org: false do
    before do
      user "foo", {}
      user "bar", {}
      user "foobar", {}
      organization "foo", { "full_name" => "Something" }
    end

    before :each do
      Chef::Config.chef_server_url = URI.join(Chef::Config.chef_server_url, "/organizations/foo")
    end

    context "and has nothing but a single group named blah" do
      group "blah", {}

      when_the_repository "has at least one of each thing" do

        before do
          # TODO We have to upload acls for an existing group due to a lack of
          # dependency detection during upload.  Fix that!
          file "acls/groups/blah.json", {}
          file "clients/x.json", { "public_key" => ChefZero::PUBLIC_KEY }
          file "containers/x.json", {}
          file "cookbooks/x/metadata.rb", cb_metadata("x", "1.0.0")
          file "cookbook_artifacts/x-1x1/metadata.rb", cb_metadata("x", "1.0.0")
          file "data_bags/x/y.json", {}
          file "environments/x.json", {}
          file "groups/x.json", {}
          file "invitations.json", [ "foo" ]
          file "members.json", [ "bar" ]
          file "org.json", { "full_name" => "wootles" }
          file "nodes/x.json", { "normal" => { "tags" => [] } }
          file "policies/x-1.0.0.json", {}
          file "policies/blah-1.0.0.json", {}
          file "policy_groups/x.json", { "policies" => { "x" => { "revision_id" => "1.0.0" }, "blah" => { "revision_id" => "1.0.0" } } }
          file "roles/x.json", {}
        end

        it "knife upload / uploads everything" do
          knife("upload /").should_succeed <<~EOM
            Updated /acls/groups/blah.json
            Created /clients/x.json
            Created /containers/x.json
            Created /cookbook_artifacts/x-1x1
            Created /cookbooks/x
            Created /data_bags/x
            Created /data_bags/x/y.json
            Created /environments/x.json
            Created /groups/x.json
            Updated /invitations.json
            Updated /members.json
            Created /nodes/x.json
            Updated /org.json
            Created /policies/blah-1.0.0.json
            Created /policies/x-1.0.0.json
            Created /policy_groups/x.json
            Created /roles/x.json
          EOM
          expect(api.get("association_requests").map { |a| a["username"] }).to eq([ "foo" ])
          expect(api.get("users").map { |a| a["user"]["username"] }).to eq([ "bar" ])
          knife("diff --name-status --diff-filter=AMT /").should_succeed ""
        end

        context "When the chef server has an identical copy of each thing" do
          before do
            file "invitations.json", [ "foo" ]
            file "members.json", [ "bar" ]
            file "org.json", { "full_name" => "Something" }

            # acl_for %w(organizations foo groups blah)
            client "x", {}
            cookbook "x", "1.0.0"
            cookbook_artifact "x", "1x1", "metadata.rb" => cb_metadata("x", "1.0.0")
            container "x", {}
            data_bag "x", { "y" => {} }
            environment "x", {}
            group "x", {}
            org_invite "foo"
            org_member "bar"
            node "x", {}
            policy "x", "1.0.0", {}
            policy "blah", "1.0.0", {}
            policy_group "x", {
              "policies" => {
                "x" => { "revision_id" => "1.0.0" },
                "blah" => { "revision_id" => "1.0.0" },
              },
            }
            role "x", {}
          end

          it "knife upload makes no changes" do
            knife("upload /").should_succeed <<~EOM
              Updated /acls/groups/blah.json
            EOM
          end
        end

        context "When the chef server has a slightly different copy of the policy revision" do
          before do
            policy "x", "1.0.0", { "run_list" => [ "blah" ] }
          end

          it "should fail because policies are not updateable" do
            knife("upload /policies/x-1.0.0.json").should_fail <<~EOM
              ERROR: /policies/x-1.0.0.json cannot be updated: policy revisions are immutable once uploaded. If you want to change the policy, create a new revision with your changes.
            EOM
          end
        end

        context "When the chef server has a slightly different copy of the cookbook artifact" do
          before do
            cookbook_artifact "x", "1x1", { "recipes" => { "default.rb" => "" } }
          end

          it "should fail because cookbook_artifacts cannot be updated" do
            knife("upload /cookbook_artifacts/x-1x1").should_fail <<~EOM
              ERROR: /cookbook_artifacts/x-1x1 cannot be updated: cookbook artifacts are immutable once uploaded.
            EOM
          end
        end

        context "When the chef server has a slightly different copy of each thing (except policy revisions)" do
          before do
            # acl_for %w(organizations foo groups blah)
            client "x", { "validator" => true }
            container "x", {}
            cookbook "x", "1.0.0", { "recipes" => { "default.rb" => "" } }
            cookbook_artifact "x", "1x1", { "metadata.rb" => cb_metadata("x", "1.0.0") }
            data_bag "x", { "y" => { "a" => "b" } }
            environment "x", { "description" => "foo" }
            group "x", { "groups" => [ "admin" ] }
            node "x", { "run_list" => [ "blah" ] }
            policy "x", "1.0.0", {}
            policy "x", "1.0.1", {}
            policy "y", "1.0.0", {}
            policy_group "x", {
              "policies" => {
                "x" => { "revision_id" => "1.0.1" },
                "y" => { "revision_id" => "1.0.0" },
              },
            }
            role "x", { "run_list" => [ "blah" ] }
          end

          it "knife upload updates everything" do
            knife("upload /").should_succeed <<~EOM
              Updated /acls/groups/blah.json
              Updated /clients/x.json
              Updated /cookbooks/x
              Updated /data_bags/x/y.json
              Updated /environments/x.json
              Updated /groups/x.json
              Updated /invitations.json
              Updated /members.json
              Updated /nodes/x.json
              Updated /org.json
              Created /policies/blah-1.0.0.json
              Updated /policy_groups/x.json
              Updated /roles/x.json
            EOM
            knife("diff --name-status --diff-filter=AMT /").should_succeed ""
          end
        end
      end

      when_the_repository "has an org.json that does not change full_name" do
        before do
          file "org.json", { "full_name" => "Something" }
        end

        it "knife upload / emits a warning for bar and adds foo and foobar" do
          knife("upload /").should_succeed ""
          expect(api.get("/")["full_name"]).to eq("Something")
        end
      end

      when_the_repository "has an org.json that changes full_name" do
        before do
          file "org.json", { "full_name" => "Something Else" }
        end

        it "knife upload / emits a warning for bar and adds foo and foobar" do
          knife("upload /").should_succeed "Updated /org.json\n"
          expect(api.get("/")["full_name"]).to eq("Something Else")
        end
      end

      context "and has invited foo and bar is already a member" do
        org_invite "foo"
        org_member "bar"

        when_the_repository "wants to invite foo, bar and foobar" do
          before do
            file "invitations.json", %w{foo bar foobar}
          end

          it "knife upload / emits a warning for bar and invites foobar" do
            knife("upload /").should_succeed "Updated /invitations.json\n", stderr: "WARN: Could not invite bar to organization foo: User bar is already in organization foo\n"
            expect(api.get("association_requests").map { |a| a["username"] }).to eq(%w{foo foobar})
            expect(api.get("users").map { |a| a["user"]["username"] }).to eq([ "bar" ])
          end
        end

        when_the_repository "wants to make foo, bar and foobar members" do
          before do
            file "members.json", %w{foo bar foobar}
          end

          it "knife upload / emits a warning for bar and adds foo and foobar" do
            knife("upload /").should_succeed "Updated /members.json\n"
            expect(api.get("association_requests").map { |a| a["username"] }).to eq([ ])
            expect(api.get("users").map { |a| a["user"]["username"] }).to eq(%w{bar foo foobar})
          end
        end

        when_the_repository "wants to invite foo and have bar as a member" do
          before do
            file "invitations.json", [ "foo" ]
            file "members.json", [ "bar" ]
          end

          it "knife upload / does nothing" do
            knife("upload /").should_succeed ""
            expect(api.get("association_requests").map { |a| a["username"] }).to eq([ "foo" ])
            expect(api.get("users").map { |a| a["user"]["username"] }).to eq([ "bar" ])
          end
        end
      end

      context "and has invited bar and foo" do
        org_invite "bar", "foo"

        when_the_repository "wants to invite foo and bar (different order)" do
          before do
            file "invitations.json", %w{foo bar}
          end

          it "knife upload / does nothing" do
            knife("upload /").should_succeed ""
            expect(api.get("association_requests").map { |a| a["username"] }).to eq(%w{bar foo})
            expect(api.get("users").map { |a| a["user"]["username"] }).to eq([ ])
          end
        end
      end

      context "and has already added bar and foo as members of the org" do
        org_member "bar", "foo"

        when_the_repository "wants to add foo and bar (different order)" do
          before do
            file "members.json", %w{foo bar}
          end

          it "knife upload / does nothing" do
            knife("upload /").should_succeed ""
            expect(api.get("association_requests").map { |a| a["username"] }).to eq([ ])
            expect(api.get("users").map { |a| a["user"]["username"] }).to eq(%w{bar foo})
          end
        end
      end
    end
  end
end
