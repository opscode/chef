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
require "chef/data_bag"

describe Chef::DataBag do
  before(:each) do
    @data_bag = Chef::DataBag.new
    allow(ChefUtils).to receive(:windows?) { false }
  end

  describe "initialize" do
    it "should be a Chef::DataBag" do
      expect(@data_bag).to be_a_kind_of(Chef::DataBag)
    end
  end

  describe "name" do
    it "should let you set the name to a string" do
      expect(@data_bag.name("clowns")).to eq("clowns")
    end

    it "should return the current name" do
      @data_bag.name "clowns"
      expect(@data_bag.name).to eq("clowns")
    end

    it "should not accept spaces" do
      expect { @data_bag.name "clown masters" }.to raise_error(ArgumentError)
    end

    it "should throw an ArgumentError if you feed it anything but a string" do
      expect { @data_bag.name({}) }.to raise_error(ArgumentError)
    end

    [ ".", "-", "_", "1"].each do |char|
      it "should allow a '#{char}' character in the data bag name" do
        expect(@data_bag.name("clown#{char}clown")).to eq("clown#{char}clown")
      end
    end
  end

  describe "deserialize" do
    before(:each) do
      @data_bag.name("mars_volta")
      @deserial = Chef::DataBag.from_hash(Chef::JSONCompat.parse(Chef::JSONCompat.to_json(@data_bag)))
    end

    it "should deserialize to a Chef::DataBag object" do
      expect(@deserial).to be_a_kind_of(Chef::DataBag)
    end

    %w{
      name
    }.each do |t|
      it "should match '#{t}'" do
        expect(@deserial.send(t.to_sym)).to eq(@data_bag.send(t.to_sym))
      end

      include_examples "to_json equivalent to Chef::JSONCompat.to_json" do
        let(:jsonable) { @data_bag }
      end
    end

  end

  describe "when saving" do
    before do
      @data_bag.name("piggly_wiggly")
      @rest = double("Chef::ServerAPI")
      allow(Chef::ServerAPI).to receive(:new).and_return(@rest)
    end

    it "should silently proceed when the data bag already exists" do
      exception = double("409 error", code: "409")
      expect(@rest).to receive(:post).and_raise(Net::HTTPClientException.new("foo", exception))
      @data_bag.save
    end

    it "should create the data bag" do
      expect(@rest).to receive(:post).with("data", @data_bag)
      @data_bag.save
    end

    it "warning case" do
      expect(ChefConfig.logger).to receive(:deprecation).with(" Databags name with period is now deprecated, consider using name without '.', you gave: \"test.test\"").at_least(:once)
      Chef::DataBag.validate_name!("test.test")
    end

    describe "when whyrun mode is enabled" do
      before do
        Chef::Config[:why_run] = true
      end
      after do
        Chef::Config[:why_run] = false
      end
      it "should not save" do
        expect(@rest).not_to receive(:post)
        @data_bag.save
      end
    end

  end
  describe "when loading" do
    describe "from an API call" do
      before do
        Chef::Config[:chef_server_url] = "https://myserver.example.com"
        @http_client = double("Chef::ServerAPI")
      end

      it "should get the data bag from the server" do
        expect(Chef::ServerAPI).to receive(:new).with("https://myserver.example.com").and_return(@http_client)
        expect(@http_client).to receive(:get).with("data/foo")
        Chef::DataBag.load("foo")
      end

      it "should return the data bag" do
        allow(Chef::ServerAPI).to receive(:new).and_return(@http_client)
        expect(@http_client).to receive(:get).with("data/foo").and_return({ "bar" => "https://myserver.example.com/data/foo/bar" })
        data_bag = Chef::DataBag.load("foo")
        expect(data_bag).to eq({ "bar" => "https://myserver.example.com/data/foo/bar" })
      end
    end

    def file_dir_stub(path, returns = true)
      expect(File).to receive(:directory?).with(path).and_return(returns)
    end

    def dir_glob_stub(path, returns = [])
      expect(Dir).to receive(:glob).with(File.join(path, "foo/*.json")).and_return(returns)
    end

    shared_examples_for "data bag in solo mode" do |data_bag_path|
      before do
        Chef::Config[:solo_legacy_mode] = true
        Chef::Config[:data_bag_path] = data_bag_path
        @paths = Array(data_bag_path)
      end

      after do
        Chef::Config[:solo_legacy_mode] = false
      end

      it "should get the data bag from the data_bag_path" do
        @paths.each do |path|
          file_dir_stub(path)
          dir_glob_stub(path)
        end
        Chef::DataBag.load("foo")
      end

      it "should get the data bag from the data_bag_path by symbolic name" do
        @paths.each do |path|
          file_dir_stub(path)
          dir_glob_stub(path)
        end
        Chef::DataBag.load(:foo)
      end

      it "should return the data bag" do
        @paths.each do |path|
          file_dir_stub(path)
          if path == @paths.first
            dir_glob_stub(path, [File.join(path, "foo/bar.json"), File.join(path, "foo/baz.json")])
          else
            dir_glob_stub(path)
          end
        end
        expect(IO).to receive(:read).with(File.join(@paths.first, "foo/bar.json")).and_return('{"id": "bar", "name": "Bob Bar" }')
        expect(IO).to receive(:read).with(File.join(@paths.first, "foo/baz.json")).and_return('{"id": "baz", "name": "John Baz" }')
        data_bag = Chef::DataBag.load("foo")
        expect(data_bag).to eq({ "bar" => { "id" => "bar", "name" => "Bob Bar" }, "baz" => { "id" => "baz", "name" => "John Baz" } })
      end

      it "should raise if data bag has items with similar names but different content" do
        @paths.each do |path|
          file_dir_stub(path)
          item_with_different_content = "{\"id\": \"bar\", \"name\": \"Bob Bar\", \"path\": \"#{path}\"}"
          expect(IO).to receive(:read).with(File.join(path, "foo/bar.json")).and_return(item_with_different_content)
          if data_bag_path.is_a?(String)
            dir_glob_stub(path, [File.join(path, "foo/bar.json"), File.join(path, "foo/baz.json")])
            item_2_with_different_content = '{"id": "bar", "name": "John Baz"}'
            expect(IO).to receive(:read).with(File.join(path, "foo/baz.json")).and_return(item_2_with_different_content)
          else
            dir_glob_stub(path, [File.join(path, "foo/bar.json")])
          end
        end
        expect { Chef::DataBag.load("foo") }.to raise_error(Chef::Exceptions::DuplicateDataBagItem)
      end

      it "should return data bag if it has items with similar names and the same content" do
        @paths.each do |path|
          file_dir_stub(path)
          dir_glob_stub(path, [File.join(path, "foo/bar.json"), File.join(path, "foo/baz.json")])
          item_with_same_content = '{"id": "bar", "name": "Bob Bar"}'
          expect(IO).to receive(:read).with(File.join(path, "foo/bar.json")).and_return(item_with_same_content)
          expect(IO).to receive(:read).with(File.join(path, "foo/baz.json")).and_return(item_with_same_content)
        end
        data_bag = Chef::DataBag.load("foo")
        test_data_bag = { "bar" => { "id" => "bar", "name" => "Bob Bar" } }
        expect(data_bag).to eq(test_data_bag)
      end

      it "should merge data bag items if there are no conflicts" do
        @paths.each_with_index do |path, index|
          file_dir_stub(path)
          dir_glob_stub(path, [File.join(path, "foo/bar.json"), File.join(path, "foo/baz.json")])
          test_item_with_same_content = '{"id": "bar", "name": "Bob Bar"}'
          expect(IO).to receive(:read).with(File.join(path, "foo/bar.json")).and_return(test_item_with_same_content)
          test_uniq_item = "{\"id\": \"baz_#{index}\", \"name\": \"John Baz\", \"path\": \"#{path}\"}"
          expect(IO).to receive(:read).with(File.join(path, "foo/baz.json")).and_return(test_uniq_item)
        end
        data_bag = Chef::DataBag.load("foo")
        test_data_bag = { "bar" => { "id" => "bar", "name" => "Bob Bar" } }
        @paths.each_with_index do |path, index|
          test_data_bag["baz_#{index}"] = { "id" => "baz_#{index}", "name" => "John Baz", "path" => path }
        end
        expect(data_bag).to eq(test_data_bag)
      end

      it "should return the data bag list" do
        @paths.each do |path|
          file_dir_stub(path)
          expect(Dir).to receive(:glob).and_return([File.join(path, "foo"), File.join(path, "bar")])
        end
        data_bag_list = Chef::DataBag.list
        expect(data_bag_list).to eq({ "bar" => "bar", "foo" => "foo" })
      end

      it "should raise an error if the configured data_bag_path is invalid" do
        file_dir_stub(@paths.first, false)
        msg = "Data bag path '#{windows? ? "C:/var/chef" : "/var/chef"}/data_bags' not found. Please create this directory."

        expect do
          Chef::DataBag.load("foo")
        end.to raise_error Chef::Exceptions::InvalidDataBagPath, msg
      end

    end

    describe "data bag with string path" do
      it_should_behave_like "data bag in solo mode", "#{windows? ? "C:/var/chef" : "/var/chef"}/data_bags"
    end

    describe "data bag with array path" do
      it_should_behave_like "data bag in solo mode", %w{data_bags data_bags_2}.map { |data_bag|
        "#{windows? ? "C:/var/chef" : "/var/chef"}/#{data_bag}"
      }
    end
  end

end
