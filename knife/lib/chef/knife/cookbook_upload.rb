#
# Author:: Adam Jacob (<adam@chef.io>)
# Author:: Christopher Walters (<cw@chef.io>)
# Author:: Nuo Yan (<yan.nuo@gmail.com>)
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

require_relative "../knife"

class Chef
  class Knife
    class CookbookUpload < Knife
      deps do
        require "chef/mixin/file_class" unless defined?(Chef::Mixin::FileClass)
        include Chef::Mixin::FileClass
        require "chef/exceptions" unless defined?(Chef::Exceptions)
        require "chef/cookbook_loader" unless defined?(Chef::CookbookLoader)
        require "chef/cookbook_uploader" unless defined?(Chef::CookbookUploader)
      end

      banner "knife cookbook upload [COOKBOOKS...] (options)"

      option :cookbook_path,
        short: "-o 'PATH:PATH'",
        long: "--cookbook-path 'PATH:PATH'",
        description: "A delimited path to search for cookbooks. On Unix the delimiter is ':', on Windows it is ';'.",
        proc: lambda { |o| o.split(File::PATH_SEPARATOR) }

      option :freeze,
        long: "--freeze",
        description: "Freeze this version of the cookbook so that it cannot be overwritten.",
        boolean: true

      option :all,
        short: "-a",
        long: "--all",
        description: "Upload all cookbooks, rather than just a single cookbook."

      option :force,
        long: "--force",
        boolean: true,
        description: "Update cookbook versions even if they have been frozen."

      option :concurrency,
        long: "--concurrency NUMBER_OF_THREADS",
        description: "How many concurrent threads will be used.",
        default: 10,
        proc: lambda { |o| o.to_i }

      option :environment,
        short: "-E",
        long: "--environment ENVIRONMENT",
        description: "Set ENVIRONMENT's version dependency match the version you're uploading.",
        default: nil

      option :depends,
        short: "-d",
        long: "--include-dependencies",
        description: "Also upload cookbook dependencies."

      option :check_dependencies,
        boolean: true, long: "--[no-]check-dependencies",
        description: "Whether or not cookbook dependencies are verified before uploading cookbook(s) to #{ChefUtils::Dist::Server::PRODUCT}. You shouldn't disable this unless you really know what you're doing.",
        default: true

      def run
        # Sanity check before we load anything from the server
        if ! config[:all] && @name_args.empty?
          show_usage
          ui.fatal("You must specify the --all flag or at least one cookbook name")
          exit 1
        end

        config[:cookbook_path] ||= Chef::Config[:cookbook_path]

        assert_environment_valid!
        version_constraints_to_update = {}
        upload_failures = 0
        upload_ok = 0

        cookbooks = []
        cookbooks_to_upload.each do |cookbook_name, cookbook|
          raise Chef::Exceptions::MetadataNotFound.new(cookbook.root_paths[0], cookbook_name) unless cookbook.has_metadata_file?

          if cookbook.metadata.name.nil?
            message = "Cookbook loaded at path [#{cookbook.root_paths[0]}] has invalid metadata: #{cookbook.metadata.errors.join("; ")}"
            raise Chef::Exceptions::MetadataNotValid, message
          end

          cookbooks << cookbook
        end

        if cookbooks.empty?
          cookbook_path = config[:cookbook_path].respond_to?(:join) ? config[:cookbook_path].join(", ") : config[:cookbook_path]
          ui.warn("Could not find any cookbooks in your cookbook path: '#{File.expand_path(cookbook_path)}'. Use --cookbook-path to specify the desired path.")
        else
          Chef::CookbookLoader.copy_to_tmp_dir_from_array(cookbooks) do |tmp_cl|
            tmp_cl.load_cookbooks
            tmp_cl.compile_metadata
            tmp_cl.freeze_versions if config[:freeze]

            cookbooks_for_upload = []
            tmp_cl.each do |cookbook_name, cookbook|
              cookbooks_for_upload << cookbook
              version_constraints_to_update[cookbook_name] = cookbook.version
            end
            if config[:all]
              if cookbooks_for_upload.any?
                begin
                  upload(cookbooks_for_upload)
                rescue Chef::Exceptions::CookbookFrozen
                  ui.warn("Not updating version constraints for some cookbooks in the environment as the cookbook is frozen.")
                  ui.error("Uploading of some of the cookbooks must be failed. Remove cookbook whose version is frozen from your cookbooks repo OR use --force option.")
                  upload_failures += 1
                rescue SystemExit => e
                  raise exit e.status
                end
                ui.info("Uploaded all cookbooks.") if upload_failures == 0
              end
            else
              tmp_cl.each do |cookbook_name, cookbook|

                upload([cookbook])
                upload_ok += 1
              rescue Exceptions::CookbookNotFoundInRepo => e
                upload_failures += 1
                ui.error("Could not find cookbook #{cookbook_name} in your cookbook path, skipping it")
                Log.debug(e)
                upload_failures += 1
              rescue Exceptions::CookbookFrozen
                ui.warn("Not updating version constraints for #{cookbook_name} in the environment as the cookbook is frozen.")
                upload_failures += 1
              rescue SystemExit => e
                raise exit e.status

              end

              if upload_failures == 0
                ui.info "Uploaded #{upload_ok} cookbook#{upload_ok == 1 ? "" : "s"}."
              elsif upload_failures > 0 && upload_ok > 0
                ui.warn "Uploaded #{upload_ok} cookbook#{upload_ok == 1 ? "" : "s"} ok but #{upload_failures} " +
                  "cookbook#{upload_failures == 1 ? "" : "s"} upload failed."
              elsif upload_failures > 0 && upload_ok == 0
                ui.error "Failed to upload #{upload_failures} cookbook#{upload_failures == 1 ? "" : "s"}."
                exit 1
              end
            end
            unless version_constraints_to_update.empty?
              update_version_constraints(version_constraints_to_update) if config[:environment]
            end
          end
        end
      end

      def server_side_cookbooks
        @server_side_cookbooks ||= Chef::CookbookVersion.list_all_versions
      end

      def justify_width
        @justify_width ||= server_side_cookbooks.map(&:size).max.to_i + 2
      end

      #
      # @param cookbook [Chef::CookbookVersion]
      #
      def left_justify_name(cookbook)
        # We only want to lookup justify width value if we're already loading
        # cookbooks to check dependencies exist in Chef Infra Server.
        if config[:check_dependencies] == true
          cookbook.name.to_s.ljust(justify_width + 10)
        else
          cookbook.name.to_s.ljust(24)
        end
      end

      def cookbooks_to_upload
        @cookbooks_to_upload ||=
          if config[:all]
            cookbook_repo.load_cookbooks
          else
            upload_set = {}
            @name_args.each do |cookbook_name|

              unless upload_set.key?(cookbook_name)
                upload_set[cookbook_name] = cookbook_repo[cookbook_name]
                if config[:depends]
                  upload_set[cookbook_name].metadata.dependencies.each_key { |dep| @name_args << dep }
                end
              end
            rescue Exceptions::CookbookNotFoundInRepo => e
              ui.error(e.message)
              Log.debug(e)

            end
            upload_set
          end
      end

      def cookbook_repo
        @cookbook_loader ||= begin
          Chef::Cookbook::FileVendor.fetch_from_disk(config[:cookbook_path])
          Chef::CookbookLoader.new(config[:cookbook_path])
        end
      end

      def update_version_constraints(new_version_constraints)
        new_version_constraints.each do |cookbook_name, version|
          environment.cookbook_versions[cookbook_name] = "= #{version}"
        end
        environment.save
      end

      def environment
        @environment ||= config[:environment] ? Environment.load(config[:environment]) : nil
      end

      private

      def assert_environment_valid!
        environment
      rescue Net::HTTPClientException => e
        if e.response.code.to_s == "404"
          ui.error "The environment #{config[:environment]} does not exist on the server, aborting."
          Log.debug(e)
          exit 1
        else
          raise
        end
      end

      def upload(cookbooks)
        cookbooks.each do |cb|
          ui.info("Uploading #{left_justify_name(cb)} [#{cb.version}]")
          check_for_broken_links!(cb)
          check_for_dependencies!(cb) if config[:check_dependencies] == true
        end
        Chef::CookbookUploader.new(cookbooks, force: config[:force], concurrency: config[:concurrency]).upload_cookbooks
      rescue Chef::Exceptions::CookbookFrozen => e
        ui.error e
        raise
      end

      def check_for_broken_links!(cookbook)
        # MUST!! dup the cookbook version object--it memoizes its
        # manifest object, but the manifest becomes invalid when you
        # regenerate the metadata
        broken_files = cookbook.dup.manifest_records_by_path.select do |path, info|
          !/[0-9a-f]{32,}/.match?(info["checksum"])
        end
        unless broken_files.empty?
          broken_filenames = Array(broken_files).map { |path, info| path }
          ui.error "The cookbook #{cookbook.name} has one or more broken files"
          ui.error "This is probably caused by broken symlinks in the cookbook directory"
          ui.error "The broken file(s) are: #{broken_filenames.join(" ")}"
          exit 1
        end
      end

      def check_for_dependencies!(cookbook)
        # for all dependencies, check if the version is on the server, or
        # the version is in the cookbooks being uploaded. If not, exit and warn the user.
        missing_dependencies = cookbook.metadata.dependencies.reject do |cookbook_name, version|
          check_server_side_cookbooks(cookbook_name, version) || check_uploading_cookbooks(cookbook_name, version)
        end

        unless missing_dependencies.empty?
          missing_cookbook_names = missing_dependencies.map { |cookbook_name, version| "'#{cookbook_name}' version '#{version}'" }
          ui.error "Cookbook #{cookbook.name} depends on cookbooks which are not currently"
          ui.error "being uploaded and cannot be found on the server."
          ui.error "The missing cookbook(s) are: #{missing_cookbook_names.join(", ")}"
          exit 1
        end
      end

      def check_server_side_cookbooks(cookbook_name, version)
        if server_side_cookbooks[cookbook_name].nil?
          false
        else
          versions = server_side_cookbooks[cookbook_name]["versions"].collect { |versions| versions["version"] }
          Log.debug "Versions of cookbook '#{cookbook_name}' returned by the server: #{versions.join(", ")}"
          server_side_cookbooks[cookbook_name]["versions"].each do |versions_hash|
            if Chef::VersionConstraint.new(version).include?(versions_hash["version"])
              Log.debug "Matched cookbook '#{cookbook_name}' with constraint '#{version}' to cookbook version '#{versions_hash["version"]}' on the server"
              return true
            end
          end
          false
        end
      end

      def check_uploading_cookbooks(cookbook_name, version)
        if (! cookbooks_to_upload[cookbook_name].nil?) && Chef::VersionConstraint.new(version).include?(cookbooks_to_upload[cookbook_name].version)
          Log.debug "Matched cookbook '#{cookbook_name}' with constraint '#{version}' to a local cookbook."
          return true
        end
        false
      end
    end
  end
end
