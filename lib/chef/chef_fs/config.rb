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
#

require_relative "../log"
require_relative "path_utils"

class Chef
  module ChefFS
    #
    # Helpers to take Chef::Config and create chef_fs and local_fs (ChefFS
    # objects representing the server and local repository, respectively).
    #
    class Config

      # Not all of our object types pluralize by adding an 's', so we map them
      # out here:
      INFLECTIONS = {
        "acls" => "acl",
        "client_keys" => "client_key",
        "clients" => "client",
        "cookbooks" => "cookbook",
        "cookbook_artifacts" => "cookbook_artifact",
        "containers" => "container",
        "data_bags" => "data_bag",
        "environments" => "environment",
        "groups" => "group",
        "nodes" => "node",
        "roles" => "role",
        "users" => "user",
        "policies" => "policy",
        "policy_groups" => "policy_group",
      }.freeze
      INFLECTIONS.each { |k, v| k.freeze; v.freeze }
      INFLECTIONS.freeze

      # ChefFS supports three modes of operation: "static", "everything", and
      # "hosted_everything". These names are antiquated since Chef 12 moved
      # multi-tenant and RBAC to the open source product. In practice, they
      # mean:
      #
      # * static: just static objects that are included in a traditional
      #   chef-repo, with no support for anything introduced in Chef 12 or
      #   later.
      # * everything: all of the objects supported by the open source Chef
      #   Server 11.x
      # * hosted_everything: (the name comes from Hosted Chef) supports
      #   everything in Chef Server 12 and later, including RBAC objects and
      #   Policyfile objects.
      #
      # The "static" and "everything" modes are used for backup and
      # upgrade/migration of older Chef Servers, so they should be considered
      # frozen in time.

      CHEF_11_OSS_STATIC_OBJECTS = %w{cookbooks data_bags environments roles}.freeze
      CHEF_11_OSS_DYNAMIC_OBJECTS = %w{clients nodes users}.freeze
      RBAC_OBJECT_NAMES = %w{acls containers groups }.freeze
      CHEF_12_OBJECTS = %w{ cookbook_artifacts policies policy_groups client_keys }.freeze

      STATIC_MODE_OBJECT_NAMES = CHEF_11_OSS_STATIC_OBJECTS
      EVERYTHING_MODE_OBJECT_NAMES = (CHEF_11_OSS_STATIC_OBJECTS + CHEF_11_OSS_DYNAMIC_OBJECTS).freeze
      HOSTED_EVERYTHING_MODE_OBJECT_NAMES = (EVERYTHING_MODE_OBJECT_NAMES + RBAC_OBJECT_NAMES + CHEF_12_OBJECTS).freeze

      #
      # Create a new Config object which can produce a chef_fs and local_fs.
      #
      # ==== Arguments
      #
      # [chef_config]
      #   A hash that looks suspiciously like +Chef::Config+.  These hash keys
      #   include:
      #
      #   :chef_repo_path::
      #     The root where all local chef object data is stored.  Mirrors
      #     +Chef::Config.chef_repo_path+
      #   :cookbook_path, node_path, ...::
      #     Paths to cookbooks/, nodes/, data_bags/, etc.  Mirrors
      #     +Chef::Config.cookbook_path+, etc.  Defaults to
      #     +<chef_repo_path>/cookbooks+, etc.
      #   :repo_mode::
      #     The directory format on disk.  'everything', 'hosted_everything' and
      #     'static'.  Default: autodetected based on whether the URL has
      #     "/organizations/NAME."
      #   :versioned_cookbooks::
      #     If true, the repository contains cookbooks with versions in their
      #     name (apache2-1.0.0).  If false, the repository just has one version
      #     of each cookbook and the directory has the cookbook name (apache2).
      #     Default: +false+
      #   :chef_server_url::
      #     The URL to the Chef server, e.g. https://api.opscode.com/organizations/foo.
      #     Used as the server for the remote chef_fs, and to "guess" repo_mode
      #     if not specified.
      #   :node_name:: The username to authenticate to the Chef server with.
      #   :client_key:: The private key for the user for authentication
      #   :environment:: The environment in which you are presently working
      #   :repo_mode::
      #     The repository mode, :hosted_everything, :everything or :static.
      #     This determines the set of subdirectories the Chef server will offer
      #     up.
      #   :versioned_cookbooks:: Whether or not to include versions in cookbook names
      #
      # [cwd]
      #   The current working directory to base relative Chef paths from.
      #   Defaults to +Dir.pwd+.
      #
      # [options]
      #   A hash of other, not-suspiciously-like-chef-config options:
      #   :cookbook_version::
      #     When downloading cookbooks, download this cookbook version instead
      #     of the latest.
      #
      # [ui]
      #   The object to print output to, with "output", "warn" and "error"
      #   (looks a little like a Chef::Knife::UI object, obtainable from
      #   Chef::Knife.ui).
      #
      # ==== Example
      #
      #   require 'chef/chef_fs/config'
      #   config = Chef::ChefFS::Config.new
      #   config.chef_fs.child('cookbooks').children.each do |cookbook|
      #     puts "Cookbook on server: #{cookbook.name}"
      #   end
      #   config.local_fs.child('cookbooks').children.each do |cookbook|
      #     puts "Local cookbook: #{cookbook.name}"
      #   end
      #
      def initialize(chef_config = Chef::Config, cwd = Dir.pwd, options = {}, ui = nil)
        @chef_config = chef_config
        @cwd = File.expand_path(cwd)
        @cookbook_version = options[:cookbook_version]

        if @chef_config[:repo_mode] == "everything" && is_hosted? && !ui.nil?
          ui.warn %Q{You have repo_mode set to 'everything', but your chef_server_url
              looks like it might be Chef Infra Server 12+ or Hosted Chef. If this is
              the case, use 'hosted_everything' or allow 'repo_mode' to default.}
        end
        # Default to getting *everything* from the server.
        unless @chef_config[:repo_mode]
          if is_hosted?
            @chef_config[:repo_mode] = "hosted_everything"
          else
            @chef_config[:repo_mode] = "everything"
          end
        end
      end

      attr_reader :chef_config
      attr_reader :cwd
      attr_reader :cookbook_version

      def is_hosted?
        @chef_config[:chef_server_url] =~ %r{/+organizations/.+}
      end

      def chef_fs
        @chef_fs ||= create_chef_fs
      end

      def create_chef_fs
        require_relative "file_system/chef_server/chef_server_root_dir"
        Chef::ChefFS::FileSystem::ChefServer::ChefServerRootDir.new("remote", @chef_config, cookbook_version: @cookbook_version)
      end

      def local_fs
        @local_fs ||= create_local_fs
      end

      def create_local_fs
        require_relative "file_system/repository/chef_repository_file_system_root_dir"
        Chef::ChefFS::FileSystem::Repository::ChefRepositoryFileSystemRootDir.new(object_paths, Array(chef_config[:chef_repo_path]).flatten, @chef_config)
      end

      # Returns the given real path's location relative to the server root.
      #
      # If chef_repo is /home/jkeiser/chef_repo,
      # and pwd is /home/jkeiser/chef_repo/cookbooks,
      # server_path('blah') == '/cookbooks/blah'
      # server_path('../roles/blah.json') == '/roles/blah'
      # server_path('../../readme.txt') == nil
      # server_path('*/*ab*') == '/cookbooks/*/*ab*'
      # server_path('/home/jkeiser/chef_repo/cookbooks/blah') == '/cookbooks/blah'
      # server_path('/home/*/chef_repo/cookbooks/blah') == nil
      #
      # If there are multiple different, manually specified paths to object locations
      # (cookbooks, roles, data bags, etc. can all have separate paths), and cwd+the
      # path reaches into one of them, we will return a path relative to the first
      # one to match it.  Otherwise we expect the path provided to be to the chef
      # repo path itself.  Paths that are not available on the server are not supported.
      #
      # Globs are allowed as well, but globs outside server paths are NOT
      # (presently) supported.  See above examples.  TODO support that.
      #
      # If the path does not reach into ANY specified directory, nil is returned.
      def server_path(file_path)
        target_path = Chef::ChefFS::PathUtils.realest_path(file_path, @cwd)

        # Check all object paths (cookbooks_dir, data_bags_dir, etc.)
        # These are either manually specified by the user or autogenerated relative
        # to chef_repo_path.
        object_paths.each_pair do |name, paths|
          paths.each do |path|
            object_abs_path = Chef::ChefFS::PathUtils.realest_path(path, @cwd)
            if relative_path = PathUtils.descendant_path(target_path, object_abs_path)
              return Chef::ChefFS::PathUtils.join("/#{name}", relative_path)
            end
          end
        end

        # Check chef_repo_path
        Array(@chef_config[:chef_repo_path]).flatten.each do |chef_repo_path|
          # We're using realest_path here but we really don't need to - we can just expand the
          # path and use realpath because a repo_path if provided *must* exist.
          realest_chef_repo_path = Chef::ChefFS::PathUtils.realest_path(chef_repo_path, @cwd)
          if Chef::ChefFS::PathUtils.os_path_eq?(target_path, realest_chef_repo_path)
            return "/"
          end
        end

        nil
      end

      # The current directory, relative to server root.  This is a case-sensitive server path.
      # It only exists if the current directory is a child of one of the recognized object_paths below.
      def base_path
        @base_path ||= server_path(@cwd)
      end

      # Print the given server path, relative to the current directory
      def format_path(entry)
        server_path = entry.respond_to?(:display_path) ? entry.display_path : entry.path
        if base_path && server_path[0, base_path.length] == base_path
          if server_path == base_path
            return "."
          elsif server_path[base_path.length, 1] == "/"
            return server_path[base_path.length + 1, server_path.length - base_path.length - 1]
          elsif base_path == "/" && server_path[0, 1] == "/"
            return server_path[1, server_path.length - 1]
          end
        end
        server_path
      end

      private

      def object_paths
        @object_paths ||= begin
          result = {}
          case @chef_config[:repo_mode]
          when "static"
            object_names = STATIC_MODE_OBJECT_NAMES
          when "hosted_everything"
            object_names = HOSTED_EVERYTHING_MODE_OBJECT_NAMES
          else
            object_names = EVERYTHING_MODE_OBJECT_NAMES
          end
          object_names.each do |object_name|
            # cookbooks -> cookbook_path
            singular_name = INFLECTIONS[object_name]
            raise "Unknown object name #{object_name}" unless singular_name

            variable_name = "#{singular_name}_path"
            paths = Array(@chef_config[variable_name]).flatten
            result[object_name] = paths.map { |path| File.expand_path(path) }
          end
          result
        end
      end
    end
  end
end
