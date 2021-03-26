#
# Author:: Xabier de Zuazo (<xabier@onddo.com>)
# Copyright:: Copyright 2014-2016, Onddo Labs, SL.
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

require_relative "unacceptable_encrypted_data_bag_item_format"
require_relative "unsupported_cipher"

class Chef::EncryptedDataBagItem

  class EncryptedDataBagRequirementsFailure < StandardError
  end

  module Assertions

    def assert_format_version_acceptable!(format_version)
      unless format_version.is_a?(Integer) && format_version >= Chef::Config[:data_bag_decrypt_minimum_version]
        raise UnacceptableEncryptedDataBagItemFormat,
          "The encrypted data bag item has format version `#{format_version}', " +
            "but the config setting 'data_bag_decrypt_minimum_version' requires version `#{Chef::Config[:data_bag_decrypt_minimum_version]}'"
      end
    end

    def assert_valid_cipher!(requested_cipher, algorithm)
      # In the future, chef may support configurable ciphers. For now, only
      # aes-256-cbc and aes-256-gcm are supported.
      unless requested_cipher == algorithm
        raise UnsupportedCipher,
          "Cipher '#{requested_cipher}' is not supported by this version of Chef. Available ciphers: ['#{ALGORITHM}', '#{AEAD_ALGORITHM}']"
      end
    end

    def assert_aead_requirements_met!(algorithm)
      unless OpenSSL::Cipher.ciphers.include?(algorithm)
        raise EncryptedDataBagRequirementsFailure, "The used Encrypted Data Bags version requires an OpenSSL version with \"#{algorithm}\" algorithm support"
      end
    end

  end

end
