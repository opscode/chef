#
# Author:: Adam Jacob (<adam@chef.io>)
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

require_relative "../config"
require_relative "../log"
require_relative "../resource/directory"
require_relative "../provider"
require_relative "file"
require "fileutils" unless defined?(FileUtils)

class Chef
  class Provider
    class Directory < Chef::Provider::File

      provides :directory

      def load_current_resource
        @current_resource = Chef::Resource::Directory.new(new_resource.name)
        current_resource.path(new_resource.path)
        if ::File.exist?(current_resource.path) && @action != :create_if_missing
          load_resource_attributes_from_file(current_resource)
        end
        current_resource
      end

      def define_resource_requirements
        # deep inside FAC we have to assert requirements, so call FACs hook to set that up
        access_controls.define_resource_requirements

        requirements.assert(:create) do |a|
          # Make sure the parent dir exists, or else fail.
          # for why run, print a message explaining the potential error.
          parent_directory = ::File.dirname(new_resource.path)
          a.assertion do
            if new_resource.recursive
              does_parent_exist = lambda do |base_dir|
                base_dir = ::File.dirname(base_dir)
                if ::File.exist?(base_dir)
                  ::File.directory?(base_dir)
                else
                  does_parent_exist.call(base_dir)
                end
              end
              does_parent_exist.call(new_resource.path)
            else
              ::File.directory?(parent_directory)
            end
          end
          a.failure_message(Chef::Exceptions::EnclosingDirectoryDoesNotExist, "Parent directory #{parent_directory} does not exist, cannot create #{new_resource.path}")
          a.whyrun("Assuming directory #{parent_directory} would have been created")
        end

        requirements.assert(:create) do |a|
          parent_directory = ::File.dirname(new_resource.path)
          a.assertion do
            if new_resource.recursive
              # find the lowest-level directory in new_resource.path that already exists
              # make sure we have write permissions to that directory
              is_parent_writable = lambda do |base_dir|
                base_dir = ::File.dirname(base_dir)
                if ::File.exist?(base_dir)
                  if Chef::FileAccessControl.writable?(base_dir)
                    true
                  elsif Chef::Util::PathHelper.is_sip_path?(base_dir, node)
                    Chef::Util::PathHelper.writable_sip_path?(base_dir)
                  else
                    false
                  end
                else
                  is_parent_writable.call(base_dir)
                end
              end
              is_parent_writable.call(new_resource.path)
            else
              # in why run mode & parent directory does not exist no permissions check is required
              # If not in why run, permissions must be valid and we rely on prior assertion that dir exists
              if !whyrun_mode? || ::File.exist?(parent_directory)
                if Chef::FileAccessControl.writable?(parent_directory)
                  true
                elsif Chef::Util::PathHelper.is_sip_path?(parent_directory, node)
                  Chef::Util::PathHelper.writable_sip_path?(new_resource.path)
                else
                  false
                end
              else
                true
              end
            end
          end
          if !::File.exist?(parent_directory)
            a.failure_message(Chef::Exceptions::EnclosingDirectoryDoesNotExist,
              "Parent directory #{parent_directory} does not exist.")
          elsif !Chef::FileAccessControl.writable?(parent_directory)
            a.failure_message(Chef::Exceptions::InsufficientPermissions,
              "Cannot create #{new_resource} at #{new_resource.path} due to insufficient permissions")
          end
        end

        requirements.assert(:delete) do |a|
          a.assertion do
            if ::File.exist?(new_resource.path)
              ::File.directory?(new_resource.path) && Chef::FileAccessControl.writable?(new_resource.path)
            else
              true
            end
          end
          a.failure_message(RuntimeError, "Cannot delete #{new_resource} at #{new_resource.path}!")
          # No why-run handling here:
          #  * if we don't have permissions, this is unlikely to be changed earlier in the run
          #  * if the target is a file (not a dir), there's no reasonable path by which this would have been changed
        end
      end

      action :create do
        unless ::File.exist?(new_resource.path)
          converge_by("create new directory #{new_resource.path}") do
            if new_resource.recursive == true
              ::FileUtils.mkdir_p(new_resource.path)
            else
              ::Dir.mkdir(new_resource.path)
            end
            logger.info("#{new_resource} created directory #{new_resource.path}")
          end
        end
        do_acl_changes
        do_selinux(true)
        load_resource_attributes_from_file(new_resource) unless Chef::Config[:why_run]
      end

      action :delete do
        if ::File.exist?(new_resource.path)
          converge_by("delete existing directory #{new_resource.path}") do
            if new_resource.recursive == true
              # we don't use rm_rf here because it masks all errors, including
              # IO errors or permission errors that would prevent the deletion
              FileUtils.rm_r(new_resource.path)
              logger.info("#{new_resource} deleted #{new_resource.path} recursively")
            else
              ::Dir.delete(new_resource.path)
              logger.info("#{new_resource} deleted #{new_resource.path}")
            end
          end
        end
      end

      private

      def managing_content?
        false
      end

    end
  end
end
