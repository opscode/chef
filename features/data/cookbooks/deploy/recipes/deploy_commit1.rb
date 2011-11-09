#
# Cookbook Name:: deploy
# Recipe:: deploy_commit1
#
# Copyright 2010, Opscode
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

deploy "deploy" do
  deploy_to "#{node[:tmpdir]}/deploy"
  repo "#{node[:tmpdir]}/test_git_repo"
  revision "commit1"
  action :deploy
end
