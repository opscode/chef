#
# Author:: Adam Jacob (<adam@chef.io>)
# Author:: Seth Falcon (<seth@chef.io>)
# Author:: Kyle Goodwin (<kgoodwin@primerevenue.com>)
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

require "chef-config/exceptions"

class Chef
  # == Chef::Exceptions
  # Chef's custom exceptions are all contained within the Chef::Exceptions
  # namespace.
  class Exceptions

    ConfigurationError = ChefConfig::ConfigurationError

    # Backcompat with Chef::ShellOut code:
    require "mixlib/shellout/exceptions"

    def self.const_missing(const_name)
      if const_name == :ShellCommandFailed
        Chef::Log.warn("Chef::Exceptions::ShellCommandFailed is deprecated, use Mixlib::ShellOut::ShellCommandFailed")
        called_from = caller[0..3].inject("Called from:\n") { |msg, trace_line| msg << "  #{trace_line}\n" }
        Chef::Log.warn(called_from)
        Mixlib::ShellOut::ShellCommandFailed
      else
        super
      end
    end

    class Application < RuntimeError; end
    class SigInt < RuntimeError; end
    class SigTerm < RuntimeError; end
    class Cron < RuntimeError; end
    class WindowsEnv < RuntimeError; end
    class Exec < RuntimeError; end
    class Execute < RuntimeError; end
    class ErlCall < RuntimeError; end
    class FileNotFound < RuntimeError; end
    class Package < RuntimeError; end
    class Service < RuntimeError; end
    class Script < RuntimeError; end
    class Route < RuntimeError; end
    class SearchIndex < RuntimeError; end
    class Override < RuntimeError; end
    class UnsupportedAction < RuntimeError; end
    class MissingLibrary < RuntimeError; end

    class CannotDetermineNodeName < RuntimeError
      def initialize
        super "Unable to determine node name: configure node_name or configure the system's hostname and fqdn"
      end
    end

    class User < RuntimeError; end
    class Group < RuntimeError; end
    class Link < RuntimeError; end
    class Mount < RuntimeError; end
    class Reboot < Exception; end # rubocop:disable Lint/InheritException
    class RebootPending < Exception; end # rubocop:disable Lint/InheritException
    class RebootFailed < Mixlib::ShellOut::ShellCommandFailed; end
    class ClientUpgraded < Exception; end # rubocop:disable Lint/InheritException
    class PrivateKeyMissing < RuntimeError; end
    class CannotWritePrivateKey < RuntimeError; end
    class RoleNotFound < RuntimeError; end
    class DuplicateRole < RuntimeError; end
    class ValidationFailed < ArgumentError; end
    class CannotValidateStaticallyError < ArgumentError; end
    class InvalidPrivateKey < ArgumentError; end
    class MissingKeyAttribute < ArgumentError; end
    class KeyCommandInputError < ArgumentError; end
    class BootstrapCommandInputError < ArgumentError
      def initialize
        super "You cannot pass both --json-attributes and --json-attribute-file. Please pass one or none."
      end
    end
    class InvalidKeyArgument < ArgumentError; end
    class InvalidKeyAttribute < ArgumentError; end
    class InvalidUserAttribute < ArgumentError; end
    class InvalidClientAttribute < ArgumentError; end
    class RedirectLimitExceeded < RuntimeError; end
    class AmbiguousRunlistSpecification < ArgumentError; end
    class CookbookFrozen < ArgumentError; end
    class CookbookNotFound < RuntimeError; end
    class OnlyApiVersion0SupportedForAction < RuntimeError; end
    # Cookbook loader used to raise an argument error when cookbook not found.
    # for back compat, need to raise an error that inherits from ArgumentError
    class CookbookNotFoundInRepo < ArgumentError; end
    class RecipeNotFound < ArgumentError; end
    # AttributeNotFound really means the attribute file could not be found
    class AttributeNotFound < RuntimeError; end
    # NoSuchAttribute is raised on access by node.read!("foo", "bar") when node["foo"]["bar"] does not exist.
    class NoSuchAttribute < RuntimeError; end
    # AttributeTypeMismatch is raised by node.write!("foo", "bar", "baz") when e.g. node["foo"] = "bar" (overwriting String with Hash)
    class AttributeTypeMismatch < RuntimeError; end
    class MissingCookbookDependency < StandardError; end # CHEF-5120
    class InvalidCommandOption < RuntimeError; end
    class CommandTimeout < RuntimeError; end
    class RequestedUIDUnavailable < RuntimeError; end
    class InvalidHomeDirectory < ArgumentError; end
    class DsclCommandFailed < RuntimeError; end
    class PlistUtilCommandFailed < RuntimeError; end
    class UserIDNotFound < ArgumentError; end
    class GroupIDNotFound < ArgumentError; end
    class ConflictingMembersInGroup < ArgumentError; end
    class InvalidResourceReference < RuntimeError; end
    class ResourceNotFound < RuntimeError; end
    class ProviderNotFound < RuntimeError; end
    NoProviderAvailable = ProviderNotFound
    class VerificationNotFound < RuntimeError; end
    class InvalidEventType < ArgumentError; end
    class MultipleIdentityError < RuntimeError; end
    # Used in Resource::ActionClass#load_current_resource to denote that
    # the resource doesn't actually exist (for example, the file does not exist)
    class CurrentValueDoesNotExist < RuntimeError; end

    # Can't find a Resource of this type that is valid on this platform.
    class NoSuchResourceType < NameError
      def initialize(short_name, node)
        super "Cannot find a resource for #{short_name} on #{node[:platform]} version #{node[:platform_version]}"
      end
    end

    class InvalidPolicybuilderCall < ArgumentError; end

    class InvalidResourceSpecification < ArgumentError; end
    class SolrConnectionError < RuntimeError; end
    class IllegalChecksumRevert < RuntimeError; end
    class CookbookVersionNameMismatch < ArgumentError; end
    class MissingParentDirectory < RuntimeError; end
    class DestinationAlreadyExists < RuntimeError; end
    class UnresolvableGitReference < RuntimeError; end
    class InvalidRemoteGitReference < RuntimeError; end
    class InvalidEnvironmentRunListSpecification < ArgumentError; end
    class InvalidDataBagItemID < ArgumentError; end
    class InvalidDataBagName < ArgumentError; end
    class EnclosingDirectoryDoesNotExist < ArgumentError; end
    # Errors originating from calls to the Win32 API
    class Win32APIError < RuntimeError; end

    # Thrown when Win32 API layer binds to non-existent Win32 function.  Occurs
    # when older versions of Windows don't support newer Win32 API functions.
    class Win32APIFunctionNotImplemented < NotImplementedError; end # rubocop:disable Lint/InheritException
    # Attempting to run windows code on a not-windows node
    class Win32NotWindows < RuntimeError; end
    class WindowsNotAdmin < RuntimeError; end
    # Attempting to access a 64-bit only resource on a 32-bit Windows system
    class Win32ArchitectureIncorrect < RuntimeError; end
    class ObsoleteDependencySyntax < ArgumentError; end
    class InvalidDataBagPath < ArgumentError; end
    class DuplicateDataBagItem < RuntimeError; end

    class PowershellCmdletException < RuntimeError; end
    class LCMParser < RuntimeError; end

    class CannotDetermineHomebrewOwner < Package; end
    class CannotDetermineWindowsInstallerType < Package; end
    class NoWindowsPackageSource < Package; end

    # Can not create staging file during file deployment
    class FileContentStagingError < RuntimeError
      def initialize(errors)
        super "Staging tempfile can not be created during file deployment.\n Errors: #{errors.join('\n')}!"
      end
    end

    # A different version of a cookbook was added to a
    # VersionedRecipeList than the one already there.
    class CookbookVersionConflict < ArgumentError; end

    # does not follow X.Y.Z format. ArgumentError?
    class InvalidPlatformVersion < ArgumentError; end
    class InvalidCookbookVersion < ArgumentError; end

    # version constraint should be a string or array, or it doesn't
    # match OP VERSION. ArgumentError?
    class InvalidVersionConstraint < ArgumentError; end

    # Version constraints are not allowed in chef-solo
    class IllegalVersionConstraint < NotImplementedError; end # rubocop:disable Lint/InheritException

    class MetadataNotValid < StandardError; end
    class MetadataNotFound < StandardError
      attr_reader :install_path
      attr_reader :cookbook_name
      def initialize(install_path, cookbook_name)
        @install_path = install_path
        @cookbook_name = cookbook_name
        super "No metadata.rb or metadata.json found for cookbook #{@cookbook_name} in #{@install_path}"
      end
    end

    # File operation attempted but no permissions to perform it
    class InsufficientPermissions < RuntimeError; end

    # Ifconfig failed
    class Ifconfig < RuntimeError; end

    # Invalid "source" parameter to a remote_file resource
    class InvalidRemoteFileURI < ArgumentError; end

    # Node::Attribute computes the merged version of of attributes
    # and makes it read-only. Attempting to modify a read-only
    # attribute will cause this error.
    class ImmutableAttributeModification < NoMethodError
      def initialize
        super "Node attributes are read-only when you do not specify which precedence level to set. " +
          %q{To set an attribute use code like `node.default["key"] = "value"'}
      end
    end

    # Merged node attributes are invalidated when the component
    # attributes are updated. Attempting to read from a stale copy
    # of merged attributes will trigger this error.
    class StaleAttributeRead < StandardError; end

    # Registry Helper throws the following errors
    class Win32RegArchitectureIncorrect < Win32ArchitectureIncorrect; end
    class Win32RegHiveMissing < ArgumentError; end
    class Win32RegKeyMissing < RuntimeError; end
    class Win32RegValueMissing < RuntimeError; end
    class Win32RegDataMissing < RuntimeError; end
    class Win32RegValueExists < RuntimeError; end
    class Win32RegNoRecursive < ArgumentError; end
    class Win32RegTypeDoesNotExist < ArgumentError; end
    class Win32RegBadType < ArgumentError; end
    class Win32RegBadValueSize < ArgumentError; end
    class Win32RegTypesMismatch < ArgumentError; end

    # incorrect input for registry_key create action throws following error
    class RegKeyValuesTypeMissing < ArgumentError; end
    class RegKeyValuesDataMissing < ArgumentError; end

    class InvalidEnvironmentPath < ArgumentError; end
    class EnvironmentNotFound < RuntimeError; end

    # File-like resource found a non-file (socket, pipe, directory, etc) at its destination
    class FileTypeMismatch < RuntimeError; end

    # File (or descendent) resource configured to manage symlink source, but
    # the symlink that is there either loops or points to a nonexistent file
    class InvalidSymlink < RuntimeError; end

    class ChildConvergeError < RuntimeError; end

    class DeprecatedFeatureError < RuntimeError
      def initalize(message)
        super("#{message} (raising error due to treat_deprecation_warnings_as_errors being set)")
      end
    end

    class MissingRole < RuntimeError
      NULL = Object.new

      attr_reader :expansion

      def initialize(message_or_expansion = NULL)
        @expansion = nil
        case message_or_expansion
        when NULL
          super()
        when String
          super
        when RunList::RunListExpansion
          @expansion = message_or_expansion
          missing_roles = @expansion.errors.join(", ")
          super("The expanded run list includes nonexistent roles: #{missing_roles}")
        end
      end

    end
    # Exception class for collecting multiple failures. Used when running
    # delayed notifications so that chef can process each delayed
    # notification even if chef client or other notifications fail.
    class MultipleFailures < StandardError
      def initialize(*args)
        super
        @all_failures = []
      end

      def message
        base = "Multiple failures occurred:\n"
        @all_failures.inject(base) do |message, (location, error)|
          message << "* #{error.class} occurred in #{location}: #{error.message}\n"
        end
      end

      def client_run_failure(exception)
        set_backtrace(exception.backtrace)
        @all_failures << [ "chef run", exception ]
      end

      def notification_failure(exception)
        @all_failures << [ "delayed notification", exception ]
      end

      def raise!
        unless empty?
          raise for_raise
        end
      end

      def empty?
        @all_failures.empty?
      end

      def for_raise
        if @all_failures.size == 1
          @all_failures[0][1]
        else
          self
        end
      end
    end

    class CookbookVersionSelection

      # Compound exception: In run_list expansion and resolution,
      # run_list items referred to cookbooks that don't exist and/or
      # have no versions available.
      class InvalidRunListItems < StandardError
        attr_reader :non_existent_cookbooks
        attr_reader :cookbooks_with_no_matching_versions

        def initialize(message, non_existent_cookbooks, cookbooks_with_no_matching_versions)
          super(message)

          @non_existent_cookbooks = non_existent_cookbooks
          @cookbooks_with_no_matching_versions = cookbooks_with_no_matching_versions
        end

        def to_json(*a)
          result = {
            "message" => message,
            "non_existent_cookbooks" => non_existent_cookbooks,
            "cookbooks_with_no_versions" => cookbooks_with_no_matching_versions,
          }
          Chef::JSONCompat.to_json(result, *a)
        end
      end

      # In run_list expansion and resolution, a constraint was
      # unsatisfiable.
      #
      # This exception may not be the complete error report. If you
      # resolve the misconfiguration represented by this exception and
      # re-solve, you may get another exception
      class UnsatisfiableRunListItem < StandardError
        attr_reader :run_list_item
        attr_reader :non_existent_cookbooks, :most_constrained_cookbooks

        # most_constrained_cookbooks: if I were to remove constraints
        # regarding these cookbooks, I would get a solution or move on
        # to the next error (deeper in the graph). An item in this list
        # may be unsatisfiable, but when resolved may also reveal
        # further unsatisfiable constraints; this condition would not be
        # reported.
        def initialize(message, run_list_item, non_existent_cookbooks, most_constrained_cookbooks)
          super(message)

          @run_list_item = run_list_item
          @non_existent_cookbooks = non_existent_cookbooks
          @most_constrained_cookbooks = most_constrained_cookbooks
        end

        def to_json(*a)
          result = {
            "message" => message,
            "unsatisfiable_run_list_item" => run_list_item,
            "non_existent_cookbooks" => non_existent_cookbooks,
            "most_constrained_cookbooks" => most_constrained_cookbooks,
          }
          Chef::JSONCompat.to_json(result, *a)
        end
      end

    end # CookbookVersionSelection

    # When the server sends a redirect, RFC 2616 states a user-agent should
    # not follow it with a method other than GET or HEAD, unless a specific
    # action is taken by the user. A redirect received as response to a
    # non-GET and non-HEAD request will thus raise an InvalidRedirect.
    class InvalidRedirect < StandardError; end

    # Raised when the content length of a download does not match the content
    # length declared in the http response.
    class ContentLengthMismatch < RuntimeError
      def initialize(response_length, content_length)
        super <<-EOF
Response body length #{response_length} does not match HTTP Content-Length header #{content_length}.
This error is most often caused by network issues (proxies, etc) outside of chef-client.
        EOF
      end
    end

    class UnsupportedPlatform < RuntimeError
      def initialize(platform)
        super "This functionality is not supported on platform #{platform}."
      end
    end

    # Raised when Chef::Config[:run_lock_timeout] is set and some other client run fails
    # to release the run lock becure Chef::Config[:run_lock_timeout] seconds pass.
    class RunLockTimeout < RuntimeError
      def initialize(duration, blocking_pid)
        super "Unable to acquire lock. Waited #{duration} seconds for #{blocking_pid} to release."
      end
    end

    class ChecksumMismatch < RuntimeError
      def initialize(res_cksum, cont_cksum)
        super "Checksum on resource (#{res_cksum}) does not match checksum on content (#{cont_cksum})"
      end
    end

    class BadProxyURI < RuntimeError; end

    # Raised by Chef::JSONCompat
    class JSON
      class EncodeError < RuntimeError; end
      class ParseError < RuntimeError; end
    end

    class InvalidSearchQuery < ArgumentError; end

    # Raised by Chef::ProviderResolver
    class AmbiguousProviderResolution < RuntimeError
      def initialize(resource, classes)
        super "Found more than one provider for #{resource.resource_name} resource: #{classes}"
      end
    end

    class AuditError < RuntimeError; end

    class AuditControlGroupDuplicate < AuditError
      def initialize(name)
        super "Control group with name '#{name}' has already been defined"
      end
    end
    class AuditNameMissing < AuditError; end
    class NoAuditsProvided < AuditError
      def initialize
        super "You must provide a block with controls"
      end
    end
    class AuditsFailed < AuditError
      def initialize(num_failed, num_total)
        super "Audit phase found failures - #{num_failed}/#{num_total} controls failed"
      end
    end

    # If a converge or audit fails, we want to wrap the output from those errors into 1 error so we can
    # see both issues in the output.  It is possible that nil will be provided.  You must call `fill_backtrace`
    # to correctly populate the backtrace with the wrapped backtraces.
    class RunFailedWrappingError < RuntimeError
      attr_reader :wrapped_errors
      def initialize(*errors)
        errors = errors.select { |e| !e.nil? }
        output = "Found #{errors.size} errors, they are stored in the backtrace"
        @wrapped_errors = errors
        super output
      end

      def fill_backtrace
        backtrace = []
        wrapped_errors.each_with_index do |e, i|
          backtrace << "#{i + 1}) #{e.class} -  #{e.message}"
          backtrace += e.backtrace if e.backtrace
          backtrace << "" unless i == wrapped_errors.length - 1
        end
        set_backtrace(backtrace)
      end
    end

    class PIDFileLockfileMatch < RuntimeError
      def initialize
        super "PID file and lockfile are not permitted to match. Specify a different location with --pid or --lockfile"
      end
    end

    class CookbookChefVersionMismatch < RuntimeError
      def initialize(chef_version, cookbook_name, cookbook_version, *constraints)
        constraint_str = constraints.map { |c| c.requirement.as_list.to_s }.join(", ")
        super "Cookbook '#{cookbook_name}' version '#{cookbook_version}' depends on chef version #{constraint_str}, but the running chef version is #{chef_version}"
      end
    end

    class CookbookOhaiVersionMismatch < RuntimeError
      def initialize(ohai_version, cookbook_name, cookbook_version, *constraints)
        constraint_str = constraints.map { |c| c.requirement.as_list.to_s }.join(", ")
        super "Cookbook '#{cookbook_name}' version '#{cookbook_version}' depends on ohai version #{constraint_str}, but the running ohai version is #{ohai_version}"
      end
    end

    class MultipleDscResourcesFound < RuntimeError
      attr_reader :resources_found
      def initialize(resources_found)
        @resources_found = resources_found
        matches_info = @resources_found.each do |r|
          if r["Module"].nil?
            "Resource #{r['Name']} was found in #{r['Module']['Name']}"
          else
            "Resource #{r['Name']} is a binary resource"
          end
        end
        super "Found multiple resources matching #{matches_info[0]["Module"]["Name"]}:\n#{(matches_info.map { |f| f["Module"]["Version"] }).uniq.join("\n")}"
      end
    end

    # exception specific to invalid usage of 'dsc_resource' resource
    class DSCModuleNameMissing < ArgumentError; end
  end
end
