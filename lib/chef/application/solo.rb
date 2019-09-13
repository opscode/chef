#
# Author:: AJ Christensen (<aj@chef.io>)
# Author:: Mark Mzyk (mmzyk@chef.io)
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

require_relative "base"

# DO NOT MAKE EDITS, see Chef::Application::Base
#
# Do not reference this class it will be removed in Chef-16
#
# @deprecated use Chef::Application::Client instead, this will be removed in Chef-16
#
class Chef::Application::Solo < Chef::Application::Base

  option :config_file,
    short: "-c CONFIG",
    long: "--config CONFIG",
    default: Chef::Config.platform_specific_path("#{Chef::Dist::CONF_DIR}/solo.rb"),
    description: "The configuration file to use."

  option :recipe_url,
    short: "-r RECIPE_URL",
    long: "--recipe-url RECIPE_URL",
    description: "Pull down a remote gzipped tarball of recipes and untar it to the cookbook cache."

  def initialize(solo: true)
    @solo_flag = solo
    super()
  end
end
