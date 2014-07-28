#
# Author:: Adam Jacob (<adam@opscode.com>)
# Copyright:: Copyright (c) 2008 Opscode, Inc.
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

describe Chef::Resource::Ruby do

  before(:each) do
    @resource = Chef::Resource::Ruby.new('fakey_fakerton')
  end

  it 'should create a new Chef::Resource::Ruby' do
    @resource.should be_a_kind_of(Chef::Resource)
    @resource.should be_a_kind_of(Chef::Resource::Ruby)
  end

  it 'should have a resource name of :ruby' do
    @resource.resource_name.should eql(:ruby)
  end

  it 'should have an interpreter of ruby' do
    @resource.interpreter.should eql('ruby')
  end

end
