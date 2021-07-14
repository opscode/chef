#
# Author:: Adam Jacob (<adam@chef.io>)
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
require "tmpdir"

describe Chef::Provider::Directory do
  let(:tmp_dir) { Dir.mktmpdir }
  let(:new_resource) { Chef::Resource::Directory.new(tmp_dir) }
  let(:node) { Chef::Node.new }
  let(:events) { Chef::EventDispatch::Dispatcher.new }
  let(:run_context) { Chef::RunContext.new(node, {}, events) }
  let(:directory) { Chef::Provider::Directory.new(new_resource, run_context) }

  describe "#load_current_resource" do
    describe "scanning file security metadata"
    describe "on unix", unix_only: true do
      describe "when the directory exists" do
        let(:dir_stat) { File::Stat.new(tmp_dir) }
        let(:expected_uid) { dir_stat.uid }
        let(:expected_gid) { dir_stat.gid }
        let(:expected_mode) { "0%o" % ( dir_stat.mode & 007777 ) }
        let(:expected_pwnam) { Etc.getpwuid(expected_uid).name }
        let(:expected_grnam) { Etc.getgrgid(expected_gid).name }

        it "describes the access mode as a String of octal integers" do
          directory.load_current_resource
          expect(directory.current_resource.mode).to eq(expected_mode)
        end

        it "when the new_resource.owner is numeric, describes the owner as a numeric uid" do
          new_resource.owner(500)
          directory.load_current_resource
          expect(directory.current_resource.owner).to eql(expected_uid)
        end

        it "when the new_resource.group is numeric, describes the group as a numeric gid" do
          new_resource.group(500)
          directory.load_current_resource
          expect(directory.current_resource.group).to eql(expected_gid)
        end

        it "when the new_resource.owner is a string, describes the owner as a string" do
          new_resource.owner("foo")
          directory.load_current_resource
          expect(directory.current_resource.owner).to eql(expected_pwnam)
        end

        it "when the new_resource.group is a string, describes the group as a string" do
          new_resource.group("bar")
          directory.load_current_resource
          expect(directory.current_resource.group).to eql(expected_grnam)
        end
      end
    end

    describe "on windows", windows_only: true do
      describe "when the directory exists" do
        it "the mode is always nil" do
          directory.load_current_resource
          expect(directory.current_resource.mode).to be nil
        end

        it "the owner is always nil" do
          directory.load_current_resource
          expect(directory.current_resource.owner).to be nil
        end

        it "the group is always nil" do
          directory.load_current_resource
          expect(directory.current_resource.group).to be nil
        end

        it "rights are always nil (incorrectly)" do
          directory.load_current_resource
          expect(directory.current_resource.rights).to be nil
        end

        it "inherits is always nil (incorrectly)" do
          directory.load_current_resource
          expect(directory.current_resource.inherits).to be nil
        end
      end
    end

    describe "when the directory does not exist" do
      before do
        FileUtils.rmdir tmp_dir
      end

      it "sets the mode, group and owner to nil" do
        directory.load_current_resource
        expect(directory.current_resource.mode).to eq(nil)
        expect(directory.current_resource.group).to eq(nil)
        expect(directory.current_resource.owner).to eq(nil)
      end
    end

  end

  describe "#define_resource_requirements" do
    describe "on unix", unix_only: true do
      it "raises an exception if the user does not exist" do
        new_resource.owner("arglebargle_iv")
        expect(Etc).to receive(:getpwnam).with("arglebargle_iv").and_raise(ArgumentError)
        directory.action = :create
        directory.load_current_resource
        expect(directory.access_controls).to receive(:define_resource_requirements).and_call_original
        directory.define_resource_requirements
        expect { directory.process_resource_requirements }.to raise_error(ArgumentError)
      end

      it "raises an exception if the group does not exist" do
        new_resource.group("arglebargle_iv")
        expect(Etc).to receive(:getgrnam).with("arglebargle_iv").and_raise(ArgumentError)
        directory.action = :create
        directory.load_current_resource
        expect(directory.access_controls).to receive(:define_resource_requirements).and_call_original
        directory.define_resource_requirements
        expect { directory.process_resource_requirements }.to raise_error(ArgumentError)
      end
    end
  end

  describe "#run_action(:create)" do
    describe "when the directory exists" do
      it "does not create the directory" do
        expect(Dir).not_to receive(:mkdir).with(new_resource.path)
        directory.run_action(:create)
      end

      it "should not set the resource as updated" do
        directory.run_action(:create)
        expect(new_resource).not_to be_updated
      end

      context "in why run mode" do
        before { Chef::Config[:why_run] = true }
        after { Chef::Config[:why_run] = false }

        it "does not modify new_resource" do
          expect(directory).not_to receive(:load_resource_attributes_from_file).with(new_resource)
          directory.run_action(:create)
        end
      end

      it "does not create the directory if parent directory is not writable" do
        allow(Chef::FileAccessControl).to receive(:writable?).and_return(false)
        expect { directory.run_action(:create) }.to raise_error(Chef::Exceptions::InsufficientPermissions)
      end
    end

    describe "when the directory does not exist" do
      before do
        FileUtils.rmdir tmp_dir
      end

      it "creates the directory" do
        directory.run_action(:create)
        expect(File.exist?(tmp_dir)).to be true
      end

      it "sets the new resource as updated" do
        directory.run_action(:create)
        expect(new_resource).to be_updated
      end
    end

    describe "when the parent directory does not exist" do
      before do
        new_resource.path "#{tmp_dir}/foobar"
        FileUtils.rmdir tmp_dir
      end

      it "raises an exception when recursive is false" do
        new_resource.recursive false
        expect { directory.run_action(:create) }.to raise_error(Chef::Exceptions::EnclosingDirectoryDoesNotExist)
      end

      it "creates the directories when recursive is true" do
        new_resource.recursive true
        directory.run_action(:create)
        expect(new_resource).to be_updated
        expect(File.exist?("#{tmp_dir}/foobar")).to be true
      end

      it "raises an exception when the parent directory is a file and recursive is true" do
        FileUtils.touch tmp_dir
        new_resource.recursive true
        expect { directory.run_action(:create) }.to raise_error(Chef::Exceptions::EnclosingDirectoryDoesNotExist)
      end
    end

    describe "on macOS" do
      before do
        allow(ChefUtils).to receive(:macos?).and_return(true)
        new_resource.path "/usr/bin/chef_test"
        new_resource.recursive false
        allow_any_instance_of(Chef::Provider::File).to receive(:do_selinux)
      end

      it "macOS cannot write to sip locations" do
        allow(::File).to receive(:directory?).and_return(true)
        allow(Chef::FileAccessControl).to receive(:writable?).and_return(false)
        expect { directory.run_action(:create) }.to raise_error(Chef::Exceptions::InsufficientPermissions)
      end

      it "macOS can write to sip exclusions" do
        new_resource.path "/usr/local/chef_test"
        allow(::File).to receive(:directory?).and_return(true)
        allow(Dir).to receive(:mkdir).and_return([true], [])
        allow(Chef::FileAccessControl).to receive(:writable?).and_return(false)
        directory.run_action(:create)
        expect(new_resource).to be_updated
      end
    end
  end

  describe "#run_action(:delete)" do
    describe "when the directory exists" do
      it "deletes the directory" do
        directory.run_action(:delete)
        expect(File.exist?(tmp_dir)).to be false
      end

      it "sets the new resource as updated" do
        directory.run_action(:delete)
        expect(new_resource).to be_updated
      end

      it "does not use rm_rf which silently consumes errors" do
        expect(FileUtils).not_to receive(:rm_rf)
        expect(FileUtils).to receive(:rm_r)
        # set recursive or FileUtils isn't used at all.
        new_resource.recursive(true)
        directory.run_action(:delete)
        # reset back...
        new_resource.recursive(false)
      end
    end

    describe "when the directory does not exist" do
      before do
        FileUtils.rmdir tmp_dir
      end

      it "does not delete the directory" do
        expect(Dir).not_to receive(:delete).with(new_resource.path)
        directory.run_action(:delete)
      end

      it "sets the new resource as updated" do
        directory.run_action(:delete)
        expect(new_resource).not_to be_updated
      end
    end

    describe "when the directory is not writable" do
      before do
        allow(Chef::FileAccessControl).to receive(:writable?).and_return(false)
      end

      it "cannot delete it and raises an exception" do
        expect { directory.run_action(:delete) }.to raise_error(RuntimeError)
      end
    end

    describe "when the target directory is a file" do
      before do
        FileUtils.rmdir tmp_dir
        FileUtils.touch tmp_dir
      end

      it "cannot delete it and raises an exception" do
        expect { directory.run_action(:delete) }.to raise_error(RuntimeError)
      end
    end
  end
end
