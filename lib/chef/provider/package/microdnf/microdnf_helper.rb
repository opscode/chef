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

require 'chef/mixin/shell_out'
require 'chef/mixin/which'
require 'singleton' unless defined?(Singleton)
require_relative 'microdnf_version'

class Chef
  class Provider
    class Package
      class MicroDnf < Chef::Provider::Package
        class MicroDnfHelper
          include Singleton
          include Chef::Mixin::ShellOut
          include Chef::Mixin::Which

          def compare_versions(version1, version2)
            version_compare([version1, version2]).to_i
          end

          # @return Array<Version>
          # NB: "options" here is the dnf_package options hash and
          # is deliberately not **opts
          def package_query(action, provides, version: nil, arch: nil, options: [])
            parameters = { 'provides' => provides, 'version' => version, 'arch' => arch }
            if options
              parameters['options'] = options.join(' ')
            end
            query_output = query(action, parameters)
            version = parse_response(query_output)
            Chef::Log.trace "parsed #{version} from microDNF helper"
            version
          end

          def microdnf(*args)
            @microdnf_path ||= microdnf_command
            shell_out!(@microdnf_path, *args, :timeout => 60)
          end

          private

          def microdnf_command
            begin
              cmd = which('microdnf')
              unless cmd
                # Overriding linter to force raise instead of fail
                # rubocop:disable Style/SignalException
                raise Chef::Exceptions::Package, 'unable to find microdnf command'
                # rubocop:enable Style/SignalException
              end
            end

            Chef::Log.trace("Setting microdnf command to: #{cmd}")
            cmd
          end

          def add_version(hash, version)
            epoch = nil
            if version =~ /(\S+):(\S+)/
              epoch = $1
              version = $2
            end
            if version =~ /(\S+)-(\S+)/
              version = $1
              release = $2
            end
            hash['epoch'] = epoch unless epoch.nil?
            hash['release'] = release unless release.nil?
            hash['version'] = version
          end

          def query(action, parameters)
            request = build_query(action, parameters)
            Chef::Log.trace "sending '#{request}' to microDNF helper"
            result = microdnf_query(request)
            Chef::Log.trace "got '#{result}' from microDNF helper"
            result
          end

          def build_query(action, parameters)
            hash = { 'action' => action }
            parameters.each do |param_name, param_value|
              hash[param_name] = param_value unless param_value.nil?
            end

            # Special handling for certain action / param combos
            if %i{whatinstalled whatavailable}.include?(action)
              unless parameters['version'].nil?
                add_version(hash, parameters['version'])
              end
            end

            hash
          end

          def split_filename(file_name)
            file_name.delete_suffix!('.rpm')
            arch_index = file_name.rindex('.')
            arch = file_name[arch_index + 1..-1]

            rel_index = file_name[0..arch_index].rindex('-').to_i
            rel = file_name[rel_index + 1...arch_index]

            ver_index = file_name[0..rel_index - 1].rindex('-').to_i
            ver = file_name[ver_index + 1...rel_index]

            epoch_index = file_name.index(':')
            if epoch_index
              epoch = file_name[0..epoch_index - 1]
              name = file_name[epoch_index + 1...ver_index]
            else
              epoch = 0
              name = file_name[0...ver_index]
            end

            [name, ver, rel, epoch, arch]
          end

          def version_tuple(version_str)
            e = '0'
            v = nil
            r = nil

            colon_index = version_str.index(':')
            if colon_index
              colon_index.to_i
            else
              colon_index = -1
            end

            if colon_index > 0
              e = version_str[0...colon_index]
            end
            dash_index = version_str.index('-').to_i
            if dash_index > 0
              tmp = version_str[colon_index + 1...dash_index]
              v = tmp if tmp
              arch_index = version_str.rindex('.').to_i
              if (arch_index > 0) && (arch_index > dash_index)
                r = version_str[dash_index + 1...arch_index]
              else
                r = version_str[dash_index + 1..-1]
              end
            else
              tmp = version_str[colon_index + 1..-1]
              unless tmp.nil?
                v = tmp
              end
            end

            [e, v, r]
          end

          def version_compare(versions)
            return 0 if versions[0].nil? || versions[1].nil?
            v1 = version_tuple(versions[0])
            v2 = version_tuple(versions[1])
            v1 <=> v2
          end

          def microdnf_query(command)
            pkg_query = (command['provides']).to_s
            pkgs = []
            if command['version']
              pkg_query << '-' << command['version']
            end

            if command['release']
              pkg_query << '-' << command['release']
            end

            if command['arch']
              pkg_query << '.' << command['arch']
            end

            if command['action'] == :whatinstalled
              cmd = "#{command['options']} "\
                    "repoquery --installed #{pkg_query}"
              microdnf(cmd.split).stdout.each_line do |line|
                pkgs.append(line.chomp)
              end
            end

            if command['action'] == :whatavailable
              cmd = "#{command['options']} "\
                    "repoquery #{pkg_query}"
              microdnf(cmd.split).stdout.each_line do |line|
                # currently there's no way to stop the metadata generation lines
                if line.chomp != 'Downloading metadata...'
                  pkgs.append(line.chomp)
                end
              end
            end

            if pkgs.empty?
              "#{command['provides']} nil nil"
            else
              pkgs.reverse!
              pkg = pkgs.first
              name, ver, rel, epoch, arch = split_filename(pkg)
              "#{name} #{epoch}:#{ver}-#{rel} #{arch}"
            end
          end

          def parse_response(output)
            array = output.split.map { |x| x == 'nil' ? nil : x }
            array.each_slice(3).map { |x| Version.new(*x) }.first
          end
        end
      end
    end
  end
end
