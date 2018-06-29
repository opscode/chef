#
# Author:: Daniel DeLeo (<dan@kallistec.com>)
# Copyright:: Copyright 2008-2017, Chef Software Inc.
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

require "chef/exceptions"
require "chef/log"
require "chef/provider"
require "fileutils"

class Chef
  class Provider
    class Git < Chef::Provider

      extend Forwardable
      provides :git

      GIT_VERSION_PATTERN = Regexp.compile('git version (\d+\.\d+.\d+)')

      def_delegator :new_resource, :destination, :cwd

      def load_current_resource
        @resolved_reference = nil
        @current_resource = Chef::Resource::Git.new(new_resource.name)
        if current_revision = find_current_revision
          current_resource.revision current_revision
        end
      end

      def define_resource_requirements
        # Parent directory of the target must exist.
        requirements.assert(:checkout, :sync) do |a|
          dirname = ::File.dirname(cwd)
          a.assertion { ::File.directory?(dirname) }
          a.whyrun("Directory #{dirname} does not exist, this run will fail unless it has been previously created. Assuming it would have been created.")
          a.failure_message(Chef::Exceptions::MissingParentDirectory,
            "Cannot clone #{new_resource} to #{cwd}, the enclosing directory #{dirname} does not exist")
        end

        requirements.assert(:checkout) do |a|
          a.assertion { target_dir_non_existent_or_empty? }
          a.failure_message(Chef::Exceptions::DestinationAlreadyExists,
            "Cannot clone #{new_resource} into #{cwd}, the destination is not a directory or not empty.")
        end

        requirements.assert(:all_actions) do |a|
          a.assertion { !(new_resource.revision =~ /^origin\//) }
          a.failure_message Chef::Exceptions::InvalidRemoteGitReference,
             "Deploying remote branches is not supported. " +
            "Specify the remote branch as a local branch for " +
            "the git repository you're deploying from " +
            "(ie: '#{new_resource.revision.gsub('origin/', '')}' rather than '#{new_resource.revision}')."
        end

        requirements.assert(:all_actions) do |a|
          # this can't be recovered from in why-run mode, because nothing that
          # we do in the course of a run is likely to create a valid target_revision
          # if we can't resolve it up front.
          a.assertion { !target_revision.nil? }
          a.failure_message Chef::Exceptions::UnresolvableGitReference,
            "Unable to parse SHA reference for '#{new_resource.revision}' in repository '#{new_resource.repository}'. " +
            "Verify your (case-sensitive) repository URL and revision.\n" +
            "`git ls-remote '#{new_resource.repository}' '#{rev_search_pattern}'` output: #{@resolved_reference}"
        end
      end

      def action_checkout
        clone
        if new_resource.enable_checkout
          checkout
        end
        enable_submodules
        add_remotes
      end

      def action_export
        run_action :checkout
        converge_by("complete the export by removing #{cwd}.git after checkout") do
          FileUtils.rm_rf(::File.join(cwd, ".git"))
        end
      end

      def action_sync
        if existing_git_clone?
          logger.trace "#{new_resource} current revision: #{current_resource.revision} target revision: #{target_revision}"
          unless current_revision_matches_target_revision?
            fetch_updates
            enable_submodules
            logger.info "#{new_resource} updated to revision #{target_revision}"
          end
          add_remotes
        else
          run_action :checkout
        end
      end

      def git_has_single_branch_option?
        @git_has_single_branch_option ||= !git_gem_version.nil? && git_gem_version >= Gem::Version.new("1.7.10")
      end

      def git_gem_version
        return @git_gem_version if defined?(@git_gem_version)
        output = git("--version").stdout
        match = GIT_VERSION_PATTERN.match(output)
        if match
          @git_gem_version = Gem::Version.new(match[1])
        else
          logger.warn "Unable to parse git version from '#{output}'"
          @git_gem_version = nil
        end
        @git_gem_version
      end

      def existing_git_clone?
        ::File.exist?(::File.join(cwd, ".git"))
      end

      def target_dir_non_existent_or_empty?
        !::File.exist?(cwd) || Dir.entries(cwd).sort == [".", ".."]
      end

      def find_current_revision
        logger.trace("#{new_resource} finding current git revision")
        if existing_git_clone?
          # 128 is returned when we're not in a git repo. this is fine
          result = git("rev-parse", "HEAD", cwd: cwd, returns: [0, 128]).stdout.strip
        end
        sha_hash?(result) ? result : nil
      end

      def add_remotes
        if new_resource.additional_remotes.length > 0
          new_resource.additional_remotes.each_pair do |remote_name, remote_url|
            converge_by("add remote #{remote_name} from #{remote_url}") do
              logger.info "#{new_resource} adding git remote #{remote_name} = #{remote_url}"
              setup_remote_tracking_branches(remote_name, remote_url)
            end
          end
        end
      end

      def clone
        converge_by("clone from #{new_resource.repository} into #{cwd}") do
          remote = new_resource.remote

          clone_cmd = ["clone"]
          clone_cmd << "-o #{remote}" unless remote == "origin"
          clone_cmd << "--depth #{new_resource.depth}" if new_resource.depth
          clone_cmd << "--no-single-branch" if new_resource.depth && git_has_single_branch_option?
          clone_cmd << "\"#{new_resource.repository}\""
          clone_cmd << "\"#{cwd}\""

          logger.info "#{new_resource} cloning repo #{new_resource.repository} to #{cwd}"
          git clone_cmd
        end
      end

      def checkout
        sha_ref = target_revision

        converge_by("checkout ref #{sha_ref} branch #{new_resource.revision}") do
          # checkout into a local branch rather than a detached HEAD
          git("branch", "-f", new_resource.checkout_branch, sha_ref, cwd: cwd)
          git("checkout", new_resource.checkout_branch, cwd: cwd)
          logger.info "#{new_resource} checked out branch: #{new_resource.revision} onto: #{new_resource.checkout_branch} reference: #{sha_ref}"
        end
      end

      def enable_submodules
        if new_resource.enable_submodules
          converge_by("enable git submodules for #{new_resource}") do
            logger.info "#{new_resource} synchronizing git submodules"
            git("submodule", "sync", cwd: cwd)
            logger.info "#{new_resource} enabling git submodules"
            # the --recursive flag means we require git 1.6.5+ now, see CHEF-1827
            git("submodule", "update", "--init", "--recursive", cwd: cwd)
          end
        end
      end

      def fetch_updates
        setup_remote_tracking_branches(new_resource.remote, new_resource.repository)
        converge_by("fetch updates for #{new_resource.remote}") do
          # since we're in a local branch already, just reset to specified revision rather than merge
          logger.trace "Fetching updates from #{new_resource.remote} and resetting to revision #{target_revision}"
          git("fetch", "--prune", new_resource.remote, cwd: cwd)
          git("fetch", new_resource.remote, "--tags", cwd: cwd)
          git("reset", "--hard", target_revision, cwd: cwd)
        end
      end

      def setup_remote_tracking_branches(remote_name, remote_url)
        converge_by("set up remote tracking branches for #{remote_url} at #{remote_name}") do
          logger.trace "#{new_resource} configuring remote tracking branches for repository #{remote_url} " + "at remote #{remote_name}"
          check_remote_command = ["config", "--get", "remote.#{remote_name}.url"]
          remote_status = git(check_remote_command, cwd: cwd, returns: [0, 1, 2])
          case remote_status.exitstatus
          when 0, 2
            # * Status 0 means that we already have a remote with this name, so we should update the url
            #   if it doesn't match the url we want.
            # * Status 2 means that we have multiple urls assigned to the same remote (not a good idea)
            #   which we can fix by replacing them all with our target url (hence the --replace-all option)

            if multiple_remotes?(remote_status) || !remote_matches?(remote_url, remote_status)
              git("config", "--replace-all", "remote.#{remote_name}.url", %{"#{remote_url}"}, cwd: cwd)
            end
          when 1
            git("remote", "add", remote_name, remote_url, cwd: cwd)
          end
        end
      end

      def multiple_remotes?(check_remote_command_result)
        check_remote_command_result.exitstatus == 2
      end

      def remote_matches?(remote_url, check_remote_command_result)
        check_remote_command_result.stdout.strip.eql?(remote_url)
      end

      def current_revision_matches_target_revision?
        (!current_resource.revision.nil?) && (target_revision.strip.to_i(16) == current_resource.revision.strip.to_i(16))
      end

      def target_revision
        @target_revision ||= begin
          if sha_hash?(new_resource.revision)
            @target_revision = new_resource.revision
          else
            @target_revision = remote_resolve_reference
          end
        end
      end

      alias :revision_slug :target_revision

      def remote_resolve_reference
        logger.trace("#{new_resource} resolving remote reference")
        # The sha pointed to by an annotated tag is identified by the
        # '^{}' suffix appended to the tag. In order to resolve
        # annotated tags, we have to search for "revision*" and
        # post-process. Special handling for 'HEAD' to ignore a tag
        # named 'HEAD'.
        @resolved_reference = git_ls_remote(rev_search_pattern)
        refs = @resolved_reference.split("\n").map { |line| line.split("\t") }
        # First try for ^{} indicating the commit pointed to by an
        # annotated tag.
        # It is possible for a user to create a tag named 'HEAD'.
        # Using such a degenerate annotated tag would be very
        # confusing. We avoid the issue by disallowing the use of
        # annotated tags named 'HEAD'.
        if rev_search_pattern != "HEAD"
          found = find_revision(refs, new_resource.revision, "^{}")
        else
          found = refs_search(refs, "HEAD")
        end
        found = find_revision(refs, new_resource.revision) if found.empty?
        found.size == 1 ? found.first[0] : nil
      end

      def find_revision(refs, revision, suffix = "")
        found = refs_search(refs, rev_match_pattern("refs/tags/", revision) + suffix)
        found = refs_search(refs, rev_match_pattern("refs/heads/", revision) + suffix) if found.empty?
        found = refs_search(refs, revision + suffix) if found.empty?
        found
      end

      def rev_match_pattern(prefix, revision)
        if revision.start_with?(prefix)
          revision
        else
          prefix + revision
        end
      end

      def rev_search_pattern
        if ["", "HEAD"].include? new_resource.revision
          "HEAD"
        else
          new_resource.revision + "*"
        end
      end

      def git_ls_remote(rev_pattern)
        git("ls-remote", "\"#{new_resource.repository}\"", "\"#{rev_pattern}\"").stdout
      end

      def refs_search(refs, pattern)
        refs.find_all { |m| m[1] == pattern }
      end

      alias git_minor_version git_gem_version

      private

      def run_options(run_opts = {})
        env = {}
        if new_resource.user
          run_opts[:user] = new_resource.user
          # Certain versions of `git` misbehave if git configuration is
          # inaccessible in $HOME. We need to ensure $HOME matches the
          # user who is executing `git` not the user running Chef.
          env["HOME"] = begin
            require "etc"
            case new_resource.user
            when Integer
              Etc.getpwuid(new_resource.user).dir
            else
              Etc.getpwnam(new_resource.user.to_s).dir
            end
          rescue ArgumentError # user not found
            raise Chef::Exceptions::User, "Could not determine HOME for specified user '#{new_resource.user}' for resource '#{new_resource.name}'"
          end
        end
        run_opts[:group] = new_resource.group if new_resource.group
        env["GIT_SSH"] = new_resource.ssh_wrapper if new_resource.ssh_wrapper
        run_opts[:log_tag] = new_resource.to_s
        run_opts[:timeout] = new_resource.timeout if new_resource.timeout
        env.merge!(new_resource.environment) if new_resource.environment
        run_opts[:environment] = env unless env.empty?
        run_opts
      end

      def git(*args, **run_opts)
        git_command = ["git", args].compact.join(" ")
        logger.trace "running #{git_command}"
        shell_out!(git_command, run_options(run_opts))
      end

      def sha_hash?(string)
        string =~ /^[0-9a-f]{40}$/
      end

    end
  end
end
