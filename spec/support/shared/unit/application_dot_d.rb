#
# Copyright:: Copyright 2016-2019, Chef Software Inc.
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

shared_examples_for "an application that loads a dot d" do
  before do
    Chef::Config[dot_d_config_name] = client_d_dir
  end

  context "when client_d_dir is set to nil" do
    let(:client_d_dir) { nil }

    it "does not raise an exception" do
      expect { app.reconfigure }.not_to raise_error
    end
  end

  context "when client_d_dir is set to a directory with configuration" do
    # We're not going to mock out globbing the directory. We want to
    # make sure that we are correctly globbing.
    let(:client_d_dir) do
      Chef::Util::PathHelper.cleanpath(
        File.join(File.dirname(__FILE__), "../../../data/client.d_00")
      )
    end

    it "loads the configuration in order" do
      expect(IO).to receive(:read).with(Pathname.new("#{client_d_dir}/00-foo.rb").cleanpath.to_s).and_return("foo 0")
      expect(IO).to receive(:read).with(Pathname.new("#{client_d_dir}/01-bar.rb").cleanpath.to_s).and_return("bar 0")
      expect(IO).to receive(:read).with(Pathname.new("#{client_d_dir}/02-strings.rb").cleanpath.to_s).and_return("strings 0")
      allow(app).to receive(:apply_config).with(anything, Chef::Config.platform_specific_path("/etc/chef/client.rb")).and_call_original.ordered
      expect(app).to receive(:apply_config).with("foo 0", Pathname.new("#{client_d_dir}/00-foo.rb").cleanpath.to_s).and_call_original.ordered
      expect(app).to receive(:apply_config).with("bar 0", Pathname.new("#{client_d_dir}/01-bar.rb").cleanpath.to_s).and_call_original.ordered
      expect(app).to receive(:apply_config).with("strings 0", Pathname.new("#{client_d_dir}/02-strings.rb").cleanpath.to_s).and_call_original.ordered
      app.reconfigure
    end
  end

  context "when client_d_dir is set to a directory without configuration" do
    let(:client_d_dir) do
      Chef::Util::PathHelper.cleanpath(
        File.join(File.dirname(__FILE__), "../../data/client.d_01")
      )
    end

    # client.d_01 has a nested folder with a rb file that if
    # executed, would raise an exception. If it is executed,
    # it means we are loading configs that are deeply nested
    # inside of client.d. For example, client.d/foo/bar.rb
    # should not run, but client.d/foo.rb should.
    it "does not raise an exception" do
      expect { app.reconfigure }.not_to raise_error
    end
  end

  context "when client_d_dir is set to a directory containing a directory named foo.rb" do
    # foo.rb as a directory should be ignored
    let(:client_d_dir) do
      Chef::Util::PathHelper.cleanpath(
        File.join(File.dirname(__FILE__), "../../data/client.d_02")
      )
    end

    it "does not raise an exception" do
      expect { app.reconfigure }.not_to raise_error
    end
  end
end
