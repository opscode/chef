#
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

class Chef
  class Provider
    class Package
      class MicroDnf < Chef::Provider::Package
        # helper class to assist in passing around name/version/arch triples
        class Version
          attr_accessor :name
          attr_accessor :version
          attr_accessor :arch

          def initialize(name, version, arch)
            @name    = name
            @version = version
            @arch    = arch
          end

          def to_s
            "#{name}-#{version}.#{arch}" unless version.nil?
          end

          def version_with_arch
            "#{version}.#{arch}" unless version.nil?
          end

          def name_with_arch
            "#{name}.#{arch}" unless name.nil?
          end

          def matches_name_and_arch?(other)
            other.version == version && other.arch == arch
          end

          def ==(other)
            name == other.name && version == other.version && arch == other.arch
          end

          alias eql? ==
        end
      end
    end
  end
end

