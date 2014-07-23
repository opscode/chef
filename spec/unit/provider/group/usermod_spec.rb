#
# Author:: AJ Christensen (<aj@opscode.com>)
# Copyright:: Copyright (c) 2008 OpsCode, Inc.
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

require 'spec_helper'

describe Chef::Provider::Group::Usermod do
  before do
    @node = Chef::Node.new
    @events = Chef::EventDispatch::Dispatcher.new
    @run_context = Chef::RunContext.new(@node, {}, @events)
    @new_resource = Chef::Resource::Group.new('wheel')
    @new_resource.members %w(all your base)
    @new_resource.excluded_members []
    @provider = Chef::Provider::Group::Usermod.new(@new_resource, @run_context)
    @provider.stub(:run_command)
  end

  describe 'modify_group_members' do

    describe 'with an empty members array' do
      before do
        @new_resource.stub(:append).and_return(true)
        @new_resource.stub(:members).and_return([])
      end

      it 'should log an appropriate message' do
        @provider.should_not_receive(:shell_out!)
        @provider.modify_group_members
      end
    end

    describe 'with supplied members' do
      platforms = {
        'openbsd' => '-G',
        'netbsd' => '-G',
        'solaris' => '-a -G',
        'suse' => '-a -G',
        'opensuse' => '-a -G',
        'smartos' => '-G',
        'omnios' => '-G'
      }

      before do
        @new_resource.stub(:members).and_return(%w(all your base))
        File.stub(:exists?).and_return(true)
      end

      it 'should raise an error when setting the entire group directly' do
        @provider.define_resource_requirements
        @provider.load_current_resource
        @provider.instance_variable_set('@group_exists', true)
        @provider.action = :modify
        lambda { @provider.run_action(@provider.process_resource_requirements) }.should raise_error(Chef::Exceptions::Group, "setting group members directly is not supported by #{@provider}, must set append true in group")
      end

      it 'should raise an error when excluded_members are set' do
        @provider.define_resource_requirements
        @provider.load_current_resource
        @provider.instance_variable_set('@group_exists', true)
        @provider.action = :modify
        @new_resource.stub(:append).and_return(true)
        @new_resource.stub(:excluded_members).and_return(['someone'])
        lambda { @provider.run_action(@provider.process_resource_requirements) }.should raise_error(Chef::Exceptions::Group, "excluded_members is not supported by #{@provider}")
      end

      platforms.each do |platform, flags|
        it "should usermod each user when the append option is set on #{platform}" do
          current_resource = @new_resource.dup
          current_resource.members([])
          @provider.current_resource = current_resource
          @node.automatic_attrs[:platform] = platform
          @new_resource.stub(:append).and_return(true)
          @provider.should_receive(:shell_out!).with("usermod #{flags} wheel all")
          @provider.should_receive(:shell_out!).with("usermod #{flags} wheel your")
          @provider.should_receive(:shell_out!).with("usermod #{flags} wheel base")
          @provider.modify_group_members
        end
      end
    end
  end

  describe 'when loading the current resource' do
    before(:each) do
      File.stub(:exists?).and_return(false)
      @provider.action = :create
      @provider.define_resource_requirements
    end

    it "should raise an error if the required binary /usr/sbin/usermod doesn't exist" do
      File.stub(:exists?).and_return(true)
      File.should_receive(:exists?).with('/usr/sbin/usermod').and_return(false)
      lambda { @provider.process_resource_requirements }.should raise_error(Chef::Exceptions::Group)
    end

    it "shouldn't raise an error if the required binaries exist" do
      File.stub(:exists?).and_return(true)
      lambda { @provider.process_resource_requirements }.should_not raise_error
    end
  end
end
