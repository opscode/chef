#
# Copyright:: Copyright (c) 2013 Noah Kantrowitz <noah@coderanger.net>
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

require 'chef/dialect'

class Chef::Dialect::Ruby < Chef::Dialect
  register_dialect :recipe, 'ruby', 'text/ruby'

  def compile_recipe(recipe, filename)
    recipe.from_file(filename)
  end

  def compile_attributes(node, filename)
    node.from_file(filename)
  end
end
