name "end_to_end"

default_source :supermarket

run_list "end_to_end::default"

cookbook "end_to_end", path: "cookbooks/end_to_end"
