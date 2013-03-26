#
# Author:: Jesse Campbell (<hikeit@gmail.com>)
# Author:: Lamont Granquist (<lamont@opscode.com>)
# Copyright:: Copyright (c) 2013 Opscode, Inc.
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

require 'uri'
require 'tempfile'
require 'chef/provider/file_content_base'

class Chef
  class Provider
    class RemoteFile
      class Content < Chef::Provider::FileContentBase

        attr_reader :raw_file_source

        private

        def file_for_provider
          Chef::Log.debug("#{@new_resource} checking for changes")

          if current_resource_matches_target_checksum?
            Chef::Log.debug("#{@new_resource} checksum matches target checksum (#{@new_resource.checksum}) - not updating")
          else
            sources = @new_resource.source
            raw_file, @raw_file_source = try_multiple_sources(sources)
          end
          raw_file
        end

        private

        # Given an array of source uris, iterate through them until one does not fail
        def try_multiple_sources(sources)
          sources = sources.dup
          source = sources.shift
          begin
            uri = URI.parse(source)
            raw_file = grab_file_from_uri(uri)
          rescue SocketError, Errno::ECONNREFUSED, Errno::ENOENT, Errno::EACCES, Timeout::Error, Net::HTTPFatalError, Net::FTPError => e
            Chef::Log.warn("#{@new_resource} cannot be downloaded from #{source}: #{e.to_s}")
            if source = sources.shift
              Chef::Log.info("#{@new_resource} trying to download from another mirror")
              retry
            else
              raise e
            end
          end
          if uri.userinfo
            uri.password = "********"
          end
          return raw_file, uri.to_s
        end

        # Given a source uri, return a Tempfile, or a File that acts like a Tempfile (close! method)
        def grab_file_from_uri(uri)
          last_modified = @new_resource.use_last_modified ? @new_resource.last_modified : nil
          etag = @new_resource.use_etag ? @new_resource.etag : nil
          uri_dup = uri.dup
          if uri_dup.userinfo
            uri_dup.password = "********"
          end
          if @current_resource.source && ( uri_dup.to_s == @current_resource.source[0] )
            last_modified ||= @new_resource.use_last_modified ? @current_resource.last_modified : nil
            etag ||= @new_resource.use_etag ? @current_resource.etag : nil
          end
          if URI::HTTP === uri
            #HTTP or HTTPS
            raw_file, mtime, etag = Chef::Provider::RemoteFile::HTTP.fetch(uri, last_modified, etag)
          elsif URI::FTP === uri
            #FTP
            raw_file, mtime = Chef::Provider::RemoteFile::FTP.fetch(uri, @new_resource.ftp_active_mode, last_modified)
            etag = nil
          elsif uri.scheme == "file"
            #local/network file
            raw_file, mtime = Chef::Provider::RemoteFile::LocalFile.fetch(uri, last_modified)
            etag = nil
          else
            raise ArgumentError, "Invalid uri. Only http(s), ftp, and file are currently supported"
          end
          unless raw_file.nil?
            @new_resource.etag etag unless @new_resource.etag
            @new_resource.last_modified mtime unless @new_resource.last_modified
          end
          return raw_file
        end

        def current_resource_matches_target_checksum?
          @new_resource.checksum && @current_resource.checksum && @current_resource.checksum =~ /^#{Regexp.escape(@new_resource.checksum)}/
        end

      end
    end
  end
end
