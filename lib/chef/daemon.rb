#
# Author:: AJ Christensen (<aj@junglist.gen.nz>)
# Copyright:: Copyright 2008-2019, Chef Software Inc.
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

# I love you Merb (lib/merb-core/server.rb)

require_relative "config"
require_relative "run_lock"
require "etc" unless defined?(Etc)

class Chef
  class Daemon
    class << self
      attr_accessor :name
      attr_accessor :runlock

      # Daemonize the current process, managing pidfiles and process uid/gid
      #
      # === Parameters
      # name<String>:: The name to be used for the pid file
      #
      def daemonize(name)
        @name = name
        @runlock = RunLock.new(pid_file)
        if runlock.test
          # We've acquired the daemon lock. Now daemonize.
          Chef::Log.info("Daemonizing..")
          begin
            exit if fork
            Process.setsid
            exit if fork
            Chef::Log.info("Forked, in #{Process.pid}. Privileges: #{Process.euid} #{Process.egid}")
            File.umask Chef::Config[:umask]
            $stdin.reopen("/dev/null")
            $stdout.reopen("/dev/null", "a")
            $stderr.reopen($stdout)
            runlock.save_pid
          rescue NotImplementedError => e
            Chef::Application.fatal!("There is no fork: #{e.message}")
          end
        else
          Chef::Application.fatal!("Chef is already running pid #{pid_from_file}")
        end
      end

      # Gets the pid file for @name
      # ==== Returns
      # String::
      #   Location of the pid file for @name
      def pid_file
        Chef::Config[:pid_file] || "/tmp/#{@name}.pid"
      end

      # Suck the pid out of pid_file
      # ==== Returns
      # Integer::
      #   The PID from pid_file
      # nil::
      #   Returned if the pid_file does not exist.
      #
      def pid_from_file
        File.read(pid_file).chomp.to_i
      rescue Errno::ENOENT, Errno::EACCES
        nil
      end

      # Change process user/group to those specified in Chef::Config
      #
      def change_privilege
        Dir.chdir("/")

        if Chef::Config[:user] && Chef::Config[:group]
          Chef::Log.info("About to change privilege to #{Chef::Config[:user]}:#{Chef::Config[:group]}")
          _change_privilege(Chef::Config[:user], Chef::Config[:group])
        elsif Chef::Config[:user]
          Chef::Log.info("About to change privilege to #{Chef::Config[:user]}")
          _change_privilege(Chef::Config[:user])
        end
      end

      # Change privileges of the process to be the specified user and group
      #
      # ==== Parameters
      # user<String>:: The user to change the process to.
      # group<String>:: The group to change the process to.
      #
      # ==== Alternatives
      # If group is left out, the user will be used (changing to user:user)
      #
      def _change_privilege(user, group = user)
        uid, gid = Process.euid, Process.egid

        begin
          target_uid = Etc.getpwnam(user).uid
        rescue ArgumentError => e
          Chef::Application.fatal!("Failed to get UID for user #{user}, does it exist? #{e.message}")
          return false
        end

        begin
          target_gid = Etc.getgrnam(group).gid
        rescue ArgumentError => e
          Chef::Application.fatal!("Failed to get GID for group #{group}, does it exist? #{e.message}")
          return false
        end

        if (uid != target_uid) || (gid != target_gid)
          Process.initgroups(user, target_gid)
          Process::GID.change_privilege(target_gid)
          Process::UID.change_privilege(target_uid)
        end
        true
      rescue Errno::EPERM => e
        Chef::Application.fatal!("Permission denied when trying to change #{uid}:#{gid} to #{target_uid}:#{target_gid}. #{e.message}")
      end
    end
  end
end
