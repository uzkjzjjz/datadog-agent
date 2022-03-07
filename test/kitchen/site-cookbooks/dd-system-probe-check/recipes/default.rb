#
# Cookbook Name:: dd-system-probe-check
# Recipe:: default
#
# Copyright (C) 2020-present Datadog
#

if !platform?('windows')
  include_recipe "::linux_use_azure_mnt"
end

# This will copy the whole file tree from COOKBOOK_NAME/files/default/tests
# to the directory where RSpec is expecting them.
base_dir = value_for_platform(
  'windows' => { 'default' => ::File.join(Chef::Config[:file_cache_path], 'system-probe') },
  'default' => '/tmp/system-probe'
)

if node['dd-system-probe-check']['bench']
  test_dest_dir = ::File.join(base_dir, "head")
else
  test_dest_dir = ::File.join(base_dir, "tests")
end

remote_directory test_dest_dir do
  source 'tests'
  mode '755'
  files_mode '755'
  sensitive true
  case
  when !platform?('windows')
    files_owner 'root'
  end
end

if node['dd-system-probe-check']['bench']
  remote_directory ::File.join(base_dir, "main") do
    source 'main'
    mode '755'
    files_mode '755'
    sensitive true
    case
    when !platform?('windows')
      files_owner 'root'
    end
  end

  cookbook_file ::File.join(base_dir, "benchstat") do
    source 'benchstat'
    mode '755'
    sensitive true
    case
    when !platform?('windows')
      owner 'root'
    end
  end
end

if platform?('windows')
  include_recipe "::windows"
else
  include_recipe "::linux"
end
