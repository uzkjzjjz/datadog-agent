require 'spec_helper'
require 'open3'

def check_output(output, wait_thr)
  test_failures = []

  output.each_line do |line|
    puts line.strip
    test_failures << line.strip if line =~ GOLANG_TEST_FAILURE
  end

  if test_failures.empty? && !wait_thr.value.success?
    test_failures << "Test command exited with status (#{wait_thr.value.exitstatus}) but no failures were captured."
  end

  test_failures
end

print `cat /etc/os-release`
print `uname -a`

describe 'functional test running directly on host' do
  it 'successfully runs' do
    Open3.popen2e("sudo", "/tmp/security-agent/testsuite", "-test.v", "-status-metrics") do |_, output, wait_thr|
      test_failures = check_output(output, wait_thr)
      expect(test_failures).to be_empty, test_failures.join("\n")
    end
  end
end

if File.readlines("/etc/os-release").grep(/SUSE/).size == 0 and ! File.exists?('/etc/rhsm')
  describe 'functional test running inside a container' do
    it 'successfully runs' do
      Open3.popen2e("sudo", "docker", "exec", "-ti", "docker-testsuite", "/tmp/security-agent/testsuite", "-test.v", "-status-metrics", "--env", "docker") do |_, output, wait_thr|
        test_failures = check_output(output, wait_thr)
        expect(test_failures).to be_empty, test_failures.join("\n")
      end
    end
  end
end
