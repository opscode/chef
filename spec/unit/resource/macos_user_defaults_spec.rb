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

require "spec_helper"

describe Chef::Resource::MacosUserDefaults do

  let(:resource) { Chef::Resource::MacosUserDefaults.new("foo") }
  let(:provider) { resource.provider_for_action(:write) }

  it "has a resource name of :macos_userdefaults" do
    expect(resource.resource_name).to eq(:macos_userdefaults)
  end

  it "the domain property defaults to NSGlobalDomain" do
    expect(resource.domain).to eq("NSGlobalDomain")
  end

  it "the value property coerces keys in hashes to strings so we can compare them with plist data" do
    resource.value "User": "/Library/Managed Installs/way_fake.log"
    expect(resource.value).to eq({ "User" => "/Library/Managed Installs/way_fake.log" })
  end

  it "the host property defaults to nil" do
    expect(resource.host).to be_nil
  end

  it "the sudo property defaults to false" do
    expect(resource.sudo).to be false
  end

  it "sets the default action as :write" do
    expect(resource.action).to eq([:write])
  end

  it "supports :write action" do
    expect { resource.action :write }.not_to raise_error
  end

  describe '#mapped_host' do
    it "uses `all_hosts` as default" do
      expect(provider.mapped_host).to eq CF::Preferences::ALL_HOSTS
    end

    it "maps `current` to corresponding constant" do
      resource.host = :current
      expect(provider.mapped_host).to eq CF::Preferences::CURRENT_HOST
    end

    it "maps `current_host` to correct corresponding constant" do
      resource.host = :current_host
      expect(provider.mapped_host).to eq CF::Preferences::CURRENT_HOST
    end
  end

  describe '#mapped_user' do
    it "uses `current_user` as default" do
      expect(provider.mapped_user).to eq CF::Preferences::CURRENT_USER
    end

    it "maps `all_users` to corresponding constant" do
      resource.user = :all_users
      expect(provider.mapped_user).to eq CF::Preferences::ALL_USERS
    end
  end

  # TODO: should be a functional/integration test
  describe "#read_preferences" do
    it "reads preference/state" do
      resource.domain = "NSGlobalDomain"
      resource.key = "AppleKeyboardUIMode"
      expect(provider.read_preferences(resource)).to be_nil
    end
  end
end
