name             "dep_test_c"
maintainer       "Opscode"
maintainer_email "do_not_reply@opscode.com"
license          "Apache 2.0"
description      "Tests cookbook versioning in environments"
version          "1.0.0"
depends          "dep_test_a", "< 2.0.0"
depends          "dep_test_b", "< 2.0.0"