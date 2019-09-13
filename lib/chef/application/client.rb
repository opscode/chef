#
# Author:: AJ Christensen (<aj@chef.io)
# Author:: Christopher Brown (<cb@chef.io>)
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
require "uri" unless defined?(URI)

# DO NOT MAKE EDITS, see Chef::Application::Base
#
# External code may call / subclass or make references to this class.
#
class Chef::Application::Client < Chef::Application::Base

  option :config_file,
    short: "-c CONFIG",
    long: "--config CONFIG",
        default: Chef::Config.platform_specific_path("#{Chef::Dist::CONF_DIR}/solo.rb"),
    description: "The configuration file to use."

  option :runlist,
    short: "-r RunlistItem,RunlistItem...",
    long: "--runlist RunlistItem,RunlistItem...",
    description: "Permanently replace current run list with specified items.",
    proc: lambda { |items|
      items = items.split(",")
      items.compact.map do |item|
        Chef::RunList::RunListItem.new(item)
      end
    }

  option :recipe_url,
    long: "--recipe-url=RECIPE_URL",
    description: "Pull down a remote archive of recipes and unpack it to the cookbook cache. Only used in local mode."

  def initialize(solo: false)
    @solo_flag = solo
    super()
  end
end
