require 'spec_helper'
require 'open3'
require 'fileutils'

GOLANG_TEST_FAILURE = /FAIL:/

def check_output(output, wait_thr)
  test_failures = []

  output.each_line do |line|
    puts line
    test_failures << line.strip if line =~ GOLANG_TEST_FAILURE
  end

  if test_failures.empty? && !wait_thr.value.success?
    test_failures << "Test command exited with status (#{wait_thr.value.exitstatus}) but no failures were captured."
  end

  test_failures
end

def regression_output(r)
  out = "REGRESSIONS\n"
  r.each do |hdr, lines|
    out += hdr
    lines.each { |l| out += l + "\n" }
  end
  out
end

print `cat /etc/os-release`
print `uname -a`

Dir.glob('/tmp/system-probe/head/**/testsuite').each do |f|
  pkg = f.delete_prefix('/tmp/system-probe/head').delete_suffix('/testsuite')
  head_results_path = File.join('/tmp/system-probe/results', pkg, 'head.txt')
  main_results_path = File.join('/tmp/system-probe/results', pkg, 'main.txt')

  describe "system-probe benchmarks for #{pkg}" do
    it 'successfully runs' do
      print "HEAD\n"
      Dir.chdir(File.dirname(f)) do
        Open3.popen2e({"DD_SYSTEM_PROBE_BPF_DIR"=>"/tmp/system-probe/head/pkg/ebpf/bytecode/build"}, "sudo", "-E", f, "-test.v", "-test.run=^$", "-test.benchmem", "-test.bench=.") do |_, output, wait_thr|
          test_failures = check_output(output, wait_thr)
          expect(test_failures).to be_empty, test_failures.join("\n")
          FileUtils.mkdir_p(File.dirname(head_results_path))
          File.write(head_results_path, output)
        end
      end

      maindir = File.join('/tmp/system-probe/main', pkg)
      if not Dir.exist?(maindir) then
        next
      end

      print "MAIN\n"
      Dir.chdir(maindir) do
        mf = File.join(maindir, 'testsuite')
        if not File.exist?(mf) then
          next
        end

        Open3.popen2e({"DD_SYSTEM_PROBE_BPF_DIR"=>"/tmp/system-probe/main/pkg/ebpf/bytecode/build"}, "sudo", "-E", mf, "-test.v", "-test.run=^$", "-test.benchmem", "-test.bench=.") do |_, output, wait_thr|
          test_failures = check_output(output, wait_thr)
          expect(test_failures).to be_empty, test_failures.join("\n")
          FileUtils.mkdir_p(File.dirname(main_results_path))
          File.write(main_results_path, output)
        end
      end

      regressions = {}
      Open3.popen2e({}, "sudo", "-E", "/tmp/system-probe/benchstat", main_results_path, head_results_path) do |_, output, wait_thr|
        header_line = nil
        section_headers = nil
        output.each_line do |line|
          if line == "\n" then
            section_headers = nil
            next
          end
          if not section_headers then
            header_line = line
            section_headers = header_line.split("  ").map { |s| s.strip }.reject { |s| s.nil? || s.strip.empty? }
            section_headers.append('stats')
            #print section_headers, "\n"
            next
          end

          data = line.split("  ").map { |s| s.strip }.reject { |s| s.nil? || s.strip.empty? }
          #print data, "\n"
          if data[3] != "~" then
            if !regressions.has_key(header_line) then
              regressions[header_line] = []
            end
            regressions[header_line].append(line)
          end
        end
      end

      expect(regressions).to be_empty, regression_output(regressions)
    end
  end
end
