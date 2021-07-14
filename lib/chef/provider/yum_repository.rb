#
# Author:: Thom May (<thom@chef.io>)
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

require_relative "../resource"
require_relative "../mixin/which"
require_relative "noop"

class Chef
  class Provider
    class YumRepository < Chef::Provider
      extend Chef::Mixin::Which

      provides :yum_repository do
        which "yum"
      end

      def load_current_resource; end

      action :create do
        template ::File.join(new_resource.reposdir, "#{new_resource.repositoryid}.repo") do
          if template_available?(new_resource.source)
            source new_resource.source
          else
            source ::File.expand_path("support/yum_repo.erb", __dir__)
            local true
          end
          sensitive new_resource.sensitive
          variables(config: new_resource)
          mode new_resource.mode
          if new_resource.make_cache
            notifies :run, "execute[yum clean metadata #{new_resource.repositoryid}]", :immediately if new_resource.clean_metadata || new_resource.clean_headers
            notifies :run, "execute[yum-makecache-#{new_resource.repositoryid}]", :immediately
            notifies :run, "ruby_block[package-cache-reload-#{new_resource.repositoryid}]", :immediately
          end
        end

        execute "yum clean metadata #{new_resource.repositoryid}" do
          command "yum clean metadata --disablerepo=* --enablerepo=#{new_resource.repositoryid}"
          action :nothing
        end

        # get the metadata for this repo only
        execute "yum-makecache-#{new_resource.repositoryid}" do
          command "yum -q -y makecache --disablerepo=* --enablerepo=#{new_resource.repositoryid}"
          action :nothing
          only_if { new_resource.enabled }
        end

        package_cache_reload_resource
      end

      action :delete do
        # clean the repo cache first
        execute "yum clean all #{new_resource.repositoryid}" do
          command "yum clean all --disablerepo=* --enablerepo=#{new_resource.repositoryid}"
          only_if "yum repolist all | grep -P '^#{new_resource.repositoryid}([ \t]|$)'"
        end

        file ::File.join(new_resource.reposdir, "#{new_resource.repositoryid}.repo") do
          action :delete
          notifies :run, "ruby_block[package-cache-reload-#{new_resource.repositoryid}]", :immediately
        end

        package_cache_reload_resource
      end

      action :makecache do
        execute "yum-makecache-#{new_resource.repositoryid}" do
          command "yum -q -y makecache --disablerepo=* --enablerepo=#{new_resource.repositoryid}"
          action :run
          only_if { new_resource.enabled }
          notifies :run, "ruby_block[package-cache-reload-#{new_resource.repositoryid}]", :immediately
        end

        package_cache_reload_resource
      end

      alias_method :action_add, :action_create
      alias_method :action_remove, :action_delete

      def package_cache_reload_resource
        ruby_block "package-cache-reload-#{new_resource.repositoryid}" do
          if ( fedora? && node["platform_version"].to_i >= 22 ) || ( rhel? && node["platform_version"].to_i >= 8 )
            block { Chef::Provider::Package::Dnf::PythonHelper.instance.restart }
          else
            block { Chef::Provider::Package::Yum::YumCache.instance.reload }
          end
          action :nothing
        end
      end

      def template_available?(path)
        !path.nil? && run_context.has_template_in_cookbook?(new_resource.cookbook_name, path)
      end

    end
  end
end

Chef::Provider::Noop.provides :yum_repository
