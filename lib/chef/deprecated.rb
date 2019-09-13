#--
# Copyright:: Copyright 2016-2019, Chef Software Inc.
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

require_relative "mixin/convert_to_class_name"

# Structured deprecations have a unique URL associated with them, which must exist before the deprecation is merged.
class Chef
  class Deprecated

    class << self
      include Chef::Mixin::ConvertToClassName

      def create(type, message, location)
        Chef::Deprecated.const_get(convert_to_class_name(type.to_s)).new(message, location)
      end
    end

    class Base
      BASE_URL = "https://docs.chef.io/deprecations_".freeze

      attr_reader :message, :location

      def initialize(msg = nil, location = nil)
        @message = msg
        @location = location
      end

      def link
        "Please see #{url} for further details and information on how to correct this problem."
      end

      # Render the URL for the deprecation documentation page.
      #
      # @return [String]
      def url
        "#{BASE_URL}#{self.class.doc_page}"
      end

      # Render the user-visible message for this deprecation.
      #
      # @return [String]
      def to_s
        "Deprecation CHEF-#{self.class.deprecation_id} from #{location}\n\n  #{message}\n\n#{link}"
      end

      # Check if this deprecation has been silenced.
      #
      # @return [Boolean]
      def silenced?
        # Check if all warnings have been silenced.
        return true if Chef::Config[:silence_deprecation_warnings] == true
        # Check if this warning has been silenced by the config.
        return true if Chef::Config[:silence_deprecation_warnings].any? do |silence_spec|
          if silence_spec.is_a? Integer
            # Integers can end up matching the line number in the `location` string
            silence_spec = "CHEF-#{silence_spec}"
          else
            # Just in case someone uses a symbol in the config by mistake.
            silence_spec = silence_spec.to_s
          end
           # Check for a silence by deprecation name, or by location.
          self.class.deprecation_key == silence_spec || self.class.deprecation_id.to_s == silence_spec || "chef-#{self.class.deprecation_id}" == silence_spec.downcase || location.include?(silence_spec)
        end
        # check if this warning has been silenced by inline comment.
        return true if location =~ /^(.*?):(\d+):in/ && begin
          # Don't buffer the whole file in memory, so read it one line at a time.
          line_no = $2.to_i
          location_file = ::File.open($1)
          (line_no - 1).times { location_file.readline } # Read all the lines we don't care about.
          relevant_line = location_file.readline
          relevant_line.match?(/#.*chef:silence_deprecation($|[^:]|:#{self.class.deprecation_key})/)
        end

        false
      end

      class << self
        attr_reader :deprecation_id, :doc_page

        # Return the deprecation key as would be used with {Chef::Deprecated.create}.
        #
        # @return [String]
        def deprecation_key
          Chef::Mixin::ConvertToClassName.convert_to_snake_case(name, "Chef::Deprecated")
        end

        # Set the ID and documentation page path for this deprecation.
        #
        # Used in subclasses to set the data for each type of deprecation.
        #
        # @example
        #   class MyDeprecation < Base
        #     target 123, "my_deprecation.html"
        #   end
        # @param id [Integer] Deprecation ID number. This must be unique among
        #   all deprecations.
        # @param page [String, nil] Optional documentation page path. If not
        #   specified, the deprecation key is used.
        # @return [void]
        def target(id, page = nil)
          @deprecation_id = id
          @doc_page = page || "#{deprecation_key}.html"
        end
      end
    end

    class InternalApi < Base
      target 0
    end

    class JsonAutoInflate < Base
      target 1
    end

    class ExitCode < Base
      target 2
    end

    # id 3 has been deleted

    class Attributes < Base
      target 4
    end

    class CustomResource < Base
      target 5, "custom_resource_cleanups.html"
    end

    class EasyInstall < Base
      target 6
    end

    class VerifyFile < Base
      target 7
    end

    class SupportsProperty < Base
      target 8
    end

    class ChefRest < Base
      target 9
    end

    class DnfPackageAllowDowngrade < Base
      target 10
    end

    class PropertyNameCollision < Base
      target 11
    end

    class LaunchdHashProperty < Base
      target 12
    end

    class ChefPlatformMethods < Base
      target 13
    end

    class RunCommand < Base
      target 14
    end

    class PackageMisc < Base
      target 15
    end

    class MultiresourceMatch < Base
      target 16
    end

    class UseInlineResources < Base
      target 17
    end

    class LocalListen < Base
      target 18
    end

    class NamespaceCollisions < Base
      target 19
    end

    class DeployResource < Base
      target 21
    end

    class ErlResource < Base
      target 22
    end

    class FreebsdPkgProvider < Base
      target 23
    end

    # id 25 was deleted

    # id 3694 was deleted

    # Returned when using the deprecated option on a property
    class Property < Base
      target 24

      def to_s
        "Deprecated resource property used from #{location}\n\n  #{message}\n\nPlease consult the resource documentation for more information."
      end
    end

    class ShellOut < Base
      target 26
    end

    class LocaleLcAll < Base
      target 27
    end

    class SoloLegacyMode < Base
      target 28
    end

    class Generic < Base
      def url
        "https://docs.chef.io/chef_deprecations_client.html"
      end

      def to_s
        "Deprecation from #{location}\n\n  #{message}\n\n#{link}"
      end
    end
  end
end
