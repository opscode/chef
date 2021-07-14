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

require "knife_spec_helper"
require "support/shared/integration/integration_helper"
require "support/shared/context/config"
require "chef/knife/cookbook_download"
require "tmpdir"

describe "knife cookbook download", :workstation do
  include IntegrationSupport
  include KnifeSupport

  include_context "default config options"

  let(:tmpdir) { Dir.mktmpdir }

  when_the_chef_server "has only one cookbook" do
    before do
      cookbook "x", "1.0.1"
    end

    it "knife cookbook download downloads the latest version" do
      knife("cookbook download -d #{tmpdir} x").should_succeed stderr: <<~EOM
        Downloading x cookbook version 1.0.1
        Downloading root_files
        Cookbook downloaded to #{tmpdir}/x-1.0.1
      EOM
    end

    it "knife cookbook download with a version downloads the specified version" do
      knife("cookbook download -d #{tmpdir} x 1.0.1").should_succeed stderr: <<~EOM
        Downloading x cookbook version 1.0.1
        Downloading root_files
        Cookbook downloaded to #{tmpdir}/x-1.0.1
      EOM
    end

    it "knife cookbook download with an unknown version raises an error" do
      expect { knife("cookbook download -d #{tmpdir} x 1.0.0") }.to raise_error(Net::HTTPClientException)
    end
  end

  when_the_chef_server "has multiple cookbook versions" do
    before do
      cookbook "x", "1.0.1"
      cookbook "x", "1.0.0"
    end

    it "knife cookbook download with no version prompts" do
      knife("cookbook download -d #{tmpdir} x", input: "2\n").should_succeed(stderr: <<~EOM, stdout: "Which version do you want to download?\n1. x 1.0.0\n2. x 1.0.1\n\n"
        Downloading x cookbook version 1.0.1
        Downloading root_files
        Cookbook downloaded to #{tmpdir}/x-1.0.1
      EOM
                                                                            )
    end
  end
end
