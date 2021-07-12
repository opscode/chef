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

describe Chef::Resource::WindowsShare do
  let(:node) do
    Chef::Node.new.tap do |n|
      n.automatic[:hostname] = "hostname"
    end
  end
  let(:events) { Chef::EventDispatch::Dispatcher.new }
  let(:run_context) { Chef::RunContext.new(node, {}, events) }
  let(:resource) { Chef::Resource::WindowsShare.new("foobar", run_context) }
  let(:provider) { resource.provider_for_action(:create) }

  it "sets resource name as :windows_share" do
    expect(resource.resource_name).to eql(:windows_share)
  end

  it "the share_name property is the name_property" do
    expect(resource.share_name).to eql("foobar")
  end

  it "sets the default action as :create" do
    expect(resource.action).to eql([:create])
  end

  it "supports :create and :delete actions" do
    expect { resource.action :create }.not_to raise_error
    expect { resource.action :delete }.not_to raise_error
  end

  it "coerces path to a single path separator format" do
    resource.path("C:/chef".freeze)
    expect(resource.path).to eql("C:\\chef")
    resource.path("C:\\chef")
    expect(resource.path).to eql("C:\\chef")
    resource.path("C:/chef".dup)
    expect(resource.path).to eql("C:\\chef")
  end

  shared_examples "when users are passed" do
    it "add hostname to user with hostname" do
      expect(users_with_hostname).to eq(result_with_hostname)
    end

    it "add hostname to user without hostname" do
      expect(users_without_hostname).to eq(result_without_hostname)
    end

    it "add hostname to user with users name downcase" do
      expect(users_with_capital_case).to eq(result_with_downcase)
    end
  end

  %w{full_users change_users read_users}.each do |users|
    context "when #{users} are passed" do
      it_behaves_like "when users are passed" do
        let(:users_without_hostname) { resource.send(users, ["mygroup"]) }
        let(:result_without_hostname) { ["hostname\\mygroup"] }
        let(:users_with_hostname) { resource.send(users, ["hostname1\\mygroup"]) }
        let(:result_with_hostname) { ["hostname1\\mygroup"] }
        let(:users_with_capital_case) { resource.send(users, ["MYGROUP"]) }
        let(:result_with_downcase) { ["hostname\\mygroup"] }
      end
    end
  end

  it "#new_resource_users" do
    resource.read_users(["mygroup"])
    resource.change_users(["mygroup"])
    provider.send(:new_resource_users)
    expect(provider.instance_variable_get(:@full_users)).to eq([])
    expect(provider.instance_variable_get(:@change_users)).to eq(["hostname\\mygroup"])
    expect(provider.instance_variable_get(:@read_users)).to eq([])
  end

  context "check user permissions need to update or not" do

    before do
      resource.read_users(["mygroup"])
      resource.change_users(["mygroup"])
      provider.send(:new_resource_users)
    end

    it "check user read permissions to update" do
      result = provider.send(:permissions_need_update?, "read")
      expect(result).to eq(false)
    end

    it "check user change permissions to update" do
      result = provider.send(:permissions_need_update?, "change")
      expect(result).to eq(true)
    end

    it "check user full permissions to update" do
      result = provider.send(:permissions_need_update?, "full")
      expect(result).to eq(false)
    end
  end
end
