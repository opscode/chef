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

require_relative "../provider"
require "etc" unless defined?(Etc)

class Chef
  class Provider
    class User < Chef::Provider

      attr_accessor :user_exists, :locked
      attr_accessor :change_desc

      def initialize(new_resource, run_context)
        super
        @user_exists = true
        @locked = nil
        @shadow_lib_ok = true
        @group_name_resolved = true
      end

      def convert_group_name
        if new_resource.gid.is_a?(String) && new_resource.gid.to_i == 0
          new_resource.gid(Etc.getgrnam(new_resource.gid).gid)
        end
      rescue ArgumentError
        @group_name_resolved = false
      end

      def load_current_resource
        @current_resource = Chef::Resource::User.new(new_resource.name)
        current_resource.username(new_resource.username)

        begin
          user_info = Etc.getpwnam(new_resource.username)
        rescue ArgumentError
          @user_exists = false
          logger.trace("#{new_resource} user does not exist")
          user_info = nil
        end

        if user_info
          current_resource.uid(user_info.uid)
          current_resource.gid(user_info.gid)
          current_resource.home(user_info.dir)
          current_resource.shell(user_info.shell)
          current_resource.password(user_info.passwd)

          if new_resource.comment
            user_info.gecos.force_encoding(new_resource.comment.encoding)
          end
          current_resource.comment(user_info.gecos)

          begin
            require "shadow"
          rescue LoadError
            @shadow_lib_ok = false
          else
            shadow_info = Shadow::Passwd.getspnam(new_resource.username)
            unless shadow_info.nil?
              current_resource.inactive(shadow_info.sp_inact&.to_i)

              # sp_expire gives time since epoch in days till expiration. Need to convert that
              # to time in seconds since epoch and output date format for comparison
              expire_date = if shadow_info.sp_expire.nil?
                              shadow_info.sp_expire
                            else
                              Time.at(shadow_info.sp_expire * 60 * 60 * 24).strftime("%Y-%m-%d")
                            end
              current_resource.expire_date(expire_date)
            end
            if new_resource.password && current_resource.password == "x"
              current_resource.password(shadow_info.sp_pwdp)
            end
          end

          convert_group_name if new_resource.gid
        end

        current_resource
      end

      def define_resource_requirements
        requirements.assert(:create, :modify, :manage, :lock, :unlock) do |a|
          a.assertion { @group_name_resolved }
          a.failure_message Chef::Exceptions::User, "Couldn't lookup integer GID for group name #{new_resource.gid}"
          a.whyrun "group name #{new_resource.gid} does not exist.  This will cause group assignment to fail.  Assuming this group will have been created previously."
        end
        requirements.assert(:all_actions) do |a|
          a.assertion { @shadow_lib_ok }
          a.failure_message Chef::Exceptions::MissingLibrary, "You must have ruby-shadow installed for password support!"
          a.whyrun "ruby-shadow is not installed. Attempts to set user password will cause failure.  Assuming that this gem will have been previously installed." \
            "Note that user update converge may report false-positive on the basis of mismatched password. "
        end
        requirements.assert(:modify, :lock, :unlock) do |a|
          a.assertion { @user_exists }
          a.failure_message(Chef::Exceptions::User, "Cannot modify user #{new_resource.username} - does not exist!")
          a.whyrun("Assuming user #{new_resource.username} would have been created")
        end
      end

      # Check to see if the user needs any changes
      #
      # === Returns
      # <true>:: If a change is required
      # <false>:: If the users are identical
      def compare_user
        @change_desc = []
        if !new_resource.home.nil? && Pathname.new(new_resource.home).cleanpath != Pathname.new(current_resource.home).cleanpath
          @change_desc << "change homedir from #{current_resource.home} to #{new_resource.home}"
        end

        %i{comment shell password uid gid expire_date inactive}.each do |user_attrib|
          new_val = new_resource.send(user_attrib)
          cur_val = current_resource.send(user_attrib)
          if !new_val.nil? && new_val.to_s != cur_val.to_s
            @change_desc << "change #{user_attrib} from #{cur_val} to #{new_val}"
          end
        end

        !@change_desc.empty?
      end

      action :create do
        if !@user_exists
          converge_by("create user #{new_resource.username}") do
            create_user
            logger.info("#{new_resource} created")
          end
        elsif compare_user
          converge_by(["alter user #{new_resource.username}"] + change_desc) do
            manage_user
            logger.info("#{new_resource} altered, #{change_desc.join(", ")}")
          end
        end
      end

      action :remove do
        return unless @user_exists

        converge_by("remove user #{new_resource.username}") do
          remove_user
          logger.info("#{new_resource} removed")
        end
      end

      action :manage do
        return unless @user_exists && compare_user

        converge_by(["manage user #{new_resource.username}"] + change_desc) do
          manage_user
          logger.info("#{new_resource} managed: #{change_desc.join(", ")}")
        end
      end

      action :modify do
        return unless compare_user

        converge_by(["modify user #{new_resource.username}"] + change_desc) do
          manage_user
          logger.info("#{new_resource} modified: #{change_desc.join(", ")}")
        end
      end

      action :lock do
        if check_lock == false
          converge_by("lock the user #{new_resource.username}") do
            lock_user
            logger.info("#{new_resource} locked")
          end
        else
          logger.debug("#{new_resource} already locked - nothing to do")
        end
      end

      action :unlock do
        if check_lock == true
          converge_by("unlock user #{new_resource.username}") do
            unlock_user
            logger.info("#{new_resource} unlocked")
          end
        else
          logger.debug("#{new_resource} already unlocked - nothing to do")
        end
      end

      def create_user
        raise NotImplementedError
      end

      def remove_user
        raise NotImplementedError
      end

      def manage_user
        raise NotImplementedError
      end

      def lock_user
        raise NotImplementedError
      end

      def unlock_user
        raise NotImplementedError
      end

      def check_lock
        raise NotImplementedError
      end

      private

      #
      # helpers for subclasses
      #

      def should_set?(sym)
        current_resource.send(sym).to_s != new_resource.send(sym).to_s && new_resource.send(sym)
      end

      def updating_home?
        return false if new_resource.home.nil?
        return true if current_resource.home.nil?

        # Pathname#cleanpath matches more edge conditions than File.expand_path()
        new_resource.home && Pathname.new(current_resource.home).cleanpath != Pathname.new(new_resource.home).cleanpath
      end
    end
  end
end
