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
require "chef/data_bag_item"

describe Chef::DataBagItem do
  let(:data_bag_item) { Chef::DataBagItem.new }

  describe "initialize" do
    it "should be a Chef::DataBagItem" do
      expect(data_bag_item).to be_a_kind_of(Chef::DataBagItem)
    end
  end

  describe "data_bag" do
    it "should let you set the data_bag to a string" do
      expect(data_bag_item.data_bag("clowns")).to eq("clowns")
    end

    it "should return the current data_bag type" do
      data_bag_item.data_bag "clowns"
      expect(data_bag_item.data_bag).to eq("clowns")
    end

    it "should not accept spaces" do
      expect { data_bag_item.data_bag "clown masters" }.to raise_error(ArgumentError)
    end

    it "should throw an ArgumentError if you feed it anything but a string" do
      expect { data_bag_item.data_bag({}) }.to raise_error(ArgumentError)
    end
  end

  describe "raw_data" do
    it "should let you set the raw_data with a hash" do
      expect { data_bag_item.raw_data = { "id" => "octahedron" } }.not_to raise_error
    end

    it "should let you set the raw_data with a hash containing symbols" do
      expect { data_bag_item.raw_data = { id: "octahedron" } }.not_to raise_error
    end

    it "should let you set the raw_data from a mash" do
      expect { data_bag_item.raw_data = Mash.new({ "id" => "octahedron" }) }.not_to raise_error
    end

    it "should raise an exception if you set the raw data without a key" do
      expect { data_bag_item.raw_data = { "monkey" => "pants" } }.to raise_error(ArgumentError)
    end

    it "should raise an exception if you set the raw data to something other than a hash" do
      expect { data_bag_item.raw_data = "katie rules" }.to raise_error(ArgumentError)
    end

    it "should accept alphanum/-/_ for the id" do
      expect { data_bag_item.raw_data = { "id" => "h1-_" } }.not_to raise_error
    end

    [ "alphanum.alphanum", ".alphanum"].each do |char|
      it "should raise deprecated warning by using id #{char}" do
        expect(ChefConfig.logger).to receive(:deprecation).with(" Data bag item ID with period is now deprecated, consider using ID without '.', you gave: \"#{char}\"").at_least(:once)
        Chef::DataBagItem.validate_id!(char)
      end
    end

    it "should raise an exception if the id contains anything but alphanum/-/_" do
      expect { data_bag_item.raw_data = { "id" => "!@#" } }.to raise_error(ArgumentError)
    end

    it "should return the raw data" do
      data_bag_item.raw_data = { "id" => "highway_of_emptiness" }
      expect(data_bag_item.raw_data).to eq({ "id" => "highway_of_emptiness" })
    end

    it "should be a Mash by default" do
      expect(data_bag_item.raw_data).to be_a_kind_of(Mash)
    end
  end

  describe "object_name" do
    let(:data_bag_item) do
      data_bag_item = Chef::DataBagItem.new
      data_bag_item.data_bag("dreams")
      data_bag_item.raw_data = { "id" => "the_beatdown" }
      data_bag_item
    end

    it "should return an object name based on the bag name and the raw_data id" do
      expect(data_bag_item.object_name).to eq("data_bag_item_dreams_the_beatdown")
    end
  end

  describe "class method object_name" do
    it "should return an object name based based on the bag name and an id" do
      expect(Chef::DataBagItem.object_name("zen", "master")).to eq("data_bag_item_zen_master")
    end
  end

  describe "class method name" do
    let(:data_bag_item) do
      data_bag_item = Chef::DataBagItem.new
      data_bag_item.data_bag("dreams")
      data_bag_item.raw_data = { "id" => "the_beatdown", "name" => "Bruce" }
      data_bag_item
    end

    it "should return the object name" do
      expect(data_bag_item.name).to eq(data_bag_item.object_name)
    end

    it "should be distinct from raw_data 'name' key" do
      expect(data_bag_item["name"]).to eq("Bruce")
      expect(data_bag_item["name"]).not_to eq(data_bag_item.object_name)
    end
  end

  describe "when used like a Hash" do
    let(:data_bag_item) do
      data_bag_item = Chef::DataBagItem.new
      data_bag_item.raw_data = { "id" => "journey", "trials" => "been through" }
      data_bag_item
    end

    it "responds to keys" do
      expect(data_bag_item.keys).to include("id")
      expect(data_bag_item.keys).to include("trials")
    end

    it "supports element reference with []" do
      expect(data_bag_item["id"]).to eq("journey")
    end

    it "implements all the methods of Hash" do
      methods = Hash.public_instance_methods
      methods.each do |m|
        expect(data_bag_item).to respond_to(m)
      end
    end
  end

  describe "from_hash" do
    context "when hash contains raw_data" do
      let(:data_bag_item) do
        Chef::DataBagItem.from_hash({ "raw_data" => { "id" => "whoa", "name" => "Bruce", "i_know" => "kung_fu" } })
      end

      it "should have the id key set" do
        expect(data_bag_item["id"]).to eq("whoa")
      end

      it "should have the name key set" do
        expect(data_bag_item["name"]).to eq("Bruce")
      end
    end

    context "when hash does not contain raw_data" do
      let(:data_bag_item) do
        Chef::DataBagItem.from_hash({ "id" => "whoa", "name" => "Bruce", "i_know" => "kung_fu" })
      end

      it "should have the id key set" do
        expect(data_bag_item["id"]).to eq("whoa")
      end

      it "should have the name key set" do
        expect(data_bag_item["name"]).to eq("Bruce")
      end
    end
  end

  describe "to_hash" do
    let(:data_bag_item) do
      data_bag_item = Chef::DataBagItem.new
      data_bag_item.data_bag("still_lost")
      data_bag_item.raw_data = { "id" => "whoa", "name" => "Bruce", "i_know" => "kung_fu" }
      data_bag_item
    end

    let!(:original_data_bag_keys) { data_bag_item.keys }

    let(:to_hash) { data_bag_item.to_hash }

    it "should return a hash" do
      expect(to_hash).to be_a_kind_of(Hash)
    end

    it "should have the raw_data keys as top level keys" do
      expect(to_hash["id"]).to eq("whoa")
      expect(to_hash["name"]).to eq("Bruce")
      expect(to_hash["i_know"]).to eq("kung_fu")
    end

    it "should have the chef_type of data_bag_item" do
      expect(to_hash["chef_type"]).to eq("data_bag_item")
    end

    it "should have the data_bag set" do
      expect(to_hash["data_bag"]).to eq("still_lost")
    end

    it "should not mutate the data_bag_item" do
      data_bag_item.to_hash
      expect(data_bag_item.keys).to eq(original_data_bag_keys)
    end
  end

  describe "when deserializing from JSON" do
    let(:data_bag_item) do
      data_bag_item = Chef::DataBagItem.new
      data_bag_item.data_bag("mars_volta")
      data_bag_item.raw_data = { "id" => "octahedron", "name" => "Bruce", "snooze" => { "finally" => :world_will } }
      data_bag_item
    end

    let(:deserial) { Chef::DataBagItem.from_hash(Chef::JSONCompat.parse(Chef::JSONCompat.to_json(data_bag_item))) }

    it "should deserialize to a Chef::DataBagItem object" do
      expect(deserial).to be_a_kind_of(Chef::DataBagItem)
    end

    it "should have a matching 'data_bag' value" do
      expect(deserial.data_bag).to eq(data_bag_item.data_bag)
    end

    it "should have a matching 'id' key" do
      expect(deserial["id"]).to eq("octahedron")
    end

    it "should have a matching 'name' key" do
      expect(deserial["name"]).to eq("Bruce")
    end

    it "should have a matching 'snooze' key" do
      expect(deserial["snooze"]).to eq({ "finally" => "world_will" })
    end

    include_examples "to_json equivalent to Chef::JSONCompat.to_json" do
      let(:jsonable) { data_bag_item }
    end
  end

  describe "when converting to a string" do
    it "converts to a string in the form data_bag_item[ID]" do
      data_bag_item["id"] = "heart of darkness"
      expect(data_bag_item.to_s).to eq("data_bag_item[heart of darkness]")
    end

    it "inspects as data_bag_item[BAG, ID, RAW_DATA]" do
      raw_data = { "id" => "heart_of_darkness", "author" => "Conrad" }
      data_bag_item.raw_data = raw_data
      data_bag_item.data_bag("books")

      expect(data_bag_item.inspect).to eq("data_bag_item[\"books\", \"heart_of_darkness\", #{raw_data.inspect}]")
    end
  end

  describe "save" do
    let(:server) { instance_double(Chef::ServerAPI) }

    let(:data_bag_item) do
      data_bag_item = Chef::DataBagItem.new
      data_bag_item["id"] = "heart of darkness"
      data_bag_item.raw_data = { "id" => "heart_of_darkness", "author" => "Conrad" }
      data_bag_item.data_bag("books")
      data_bag_item
    end

    before do
      expect(Chef::ServerAPI).to receive(:new).and_return(server)
    end

    it "should update the item when it already exists" do
      expect(server).to receive(:put).with("data/books/heart_of_darkness", data_bag_item)
      data_bag_item.save
    end

    it "should create if the item is not found" do
      exception = double("404 error", code: "404")
      expect(server).to receive(:put).and_raise(Net::HTTPClientException.new("foo", exception))
      expect(server).to receive(:post).with("data/books", data_bag_item)
      data_bag_item.save
    end

    describe "when whyrun mode is enabled" do
      before do
        Chef::Config[:why_run] = true
      end
      after do
        Chef::Config[:why_run] = false
      end

      it "should not save" do
        expect(server).not_to receive(:put)
        expect(server).not_to receive(:post)
        data_bag_item.data_bag("books")
        data_bag_item.save
      end
    end

  end

  describe "destroy" do
    let(:server) { instance_double(Chef::ServerAPI) }

    let(:data_bag_item) do
      data_bag_item = Chef::DataBagItem.new
      data_bag_item.data_bag("a_baggy_bag")
      data_bag_item.raw_data = { "id" => "some_id" }
      data_bag_item
    end

    it "should set default parameters" do
      expect(Chef::ServerAPI).to receive(:new).and_return(server)
      expect(server).to receive(:delete).with("data/a_baggy_bag/data_bag_item_a_baggy_bag_some_id")

      data_bag_item.destroy
    end
  end

  describe "when loading" do
    before do
      data_bag_item.raw_data = { "id" => "charlie", "shell" => "zsh", "ssh_keys" => %w{key1 key2} }
      data_bag_item.data_bag("users")
    end

    describe "from an API call" do
      let(:http_client) { double("Chef::ServerAPI") }

      before do
        allow(Chef::ServerAPI).to receive(:new).and_return(http_client)
      end

      it "converts raw data to a data bag item" do
        expect(http_client).to receive(:get).with("data/users/charlie").and_return(data_bag_item.to_hash)
        item = Chef::DataBagItem.load(:users, "charlie")
        expect(item).to be_a_kind_of(Chef::DataBagItem)
        expect(item).to eq(data_bag_item)
      end

      it "does not convert when a DataBagItem is returned from the API call" do
        expect(http_client).to receive(:get).with("data/users/charlie").and_return(data_bag_item)
        item = Chef::DataBagItem.load(:users, "charlie")
        expect(item).to be_a_kind_of(Chef::DataBagItem)
        expect(item).to equal(data_bag_item)
      end
    end

    describe "in solo mode" do
      before do
        Chef::Config[:solo_legacy_mode] = true
      end

      after do
        Chef::Config[:solo_legacy_mode] = false
      end

      it "converts the raw data to a data bag item" do
        expect(Chef::DataBag).to receive(:load).with("users").and_return({ "charlie" => data_bag_item.to_hash })
        item = Chef::DataBagItem.load("users", "charlie")
        expect(item).to be_a_kind_of(Chef::DataBagItem)
        expect(item).to eq(data_bag_item)
      end

      it "raises an exception for unknown items" do
        expect(Chef::DataBag).to receive(:load).with("users").and_return({ "charlie" => data_bag_item.to_hash })
        expect { Chef::DataBagItem.load("users", "wonka") }.to raise_error Chef::Exceptions::InvalidDataBagItemID
      end
    end
  end
end
