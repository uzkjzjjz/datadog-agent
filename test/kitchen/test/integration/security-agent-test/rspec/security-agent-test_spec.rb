require 'spec_helper'

print `cat /etc/os-release`
print `uname -a`

describe 'functional test running directly on host' do
  it 'successfully runs' do
    output = `sudo /tmp/security-agent/testsuite -test.v -status-metrics 1>&2`
    retval = $?
    expect(retval).to eq(0)
  end
end

if File.readlines("/etc/os-release").grep(/SUSE/).size == 0 and ! File.exists?('/etc/rhsm')
  describe 'functional test running inside a container' do
    it 'successfully runs' do
      output = `sudo docker exec -ti docker-testsuite /tmp/security-agent/testsuite -test.v -status-metrics --env docker 1>&2`
      retval = $?
      expect(retval).to eq(0)
    end
  end
end
