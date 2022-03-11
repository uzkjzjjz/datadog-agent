require 'spec_helper'
require 'open3'
require 'fileutils'

GOLANG_TEST_FAILURE = /FAIL:/
TEST_RUN_COUNT = 10

def check_output(output, wait_thr, out_file)
  test_failures = []

  FileUtils.mkdir_p(File.dirname(out_file))
  File.open(out_file, "a") do |of|
    output.each_line do |line|
      puts line
      of.write(line)
      test_failures << line.strip if line =~ GOLANG_TEST_FAILURE
    end
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
    lines.each { |l| out += l }
  end
  out
end

def run_test(basedir, pkg, results_file)
  pkg_dir = File.join(basedir, pkg)
  if not Dir.exist?(pkg_dir) then
    return
  end

  f = File.join(pkg_dir, 'testsuite')
  if not File.exist?(f) then
    return
  end

  Dir.chdir(pkg_dir) do
    Open3.popen2e({"DD_SYSTEM_PROBE_BPF_DIR"=> File.join(basedir, "pkg/ebpf/bytecode/build")}, "sudo", "-E", f, "-test.v", "-test.run=^$", "-test.benchmem", "-test.bench=.") do |_, output, wait_thr|
      test_failures = check_output(output, wait_thr, results_file)
      expect(test_failures).to be_empty, test_failures.join("\n")
    end
  end
end

print `cat /etc/os-release`
print `uname -a`

# disable address space randomization
system('sudo printf 0 > /proc/sys/kernel/randomize_va_space')
# disable Intel turbo
if File.exist?('/sys/devices/system/cpu/intel_pstate/no_turbo') then
  system('sudo printf 1 > /sys/devices/system/cpu/intel_pstate/no_turbo')
end
# disable cpu scaling
num_cpus = `nproc`.to_i
0.upto(num_cpus - 1) do |core|
  sg = "/sys/devices/system/cpu/cpu#{core}/cpufreq/scaling_governor"
  if File.exist?(sg) then
    system("sudo printf performance > #{sg}")
  end
end

Dir.glob('/tmp/system-probe/head/**/testsuite').each do |f|
  pkg = f.delete_prefix('/tmp/system-probe/head').delete_suffix('/testsuite')
  main_results_path = File.join('/tmp/system-probe/results', pkg, 'main.txt')
  head_results_path = File.join('/tmp/system-probe/results', pkg, 'head.txt')

  describe "system-probe benchmarks for #{pkg}" do
    it 'successfully runs' do
      TEST_RUN_COUNT.times {
        # alternate between them for less noisy results
        puts "MAIN\n"
        run_test('/tmp/system-probe/main', pkg, main_results_path)
        puts "HEAD\n"
        run_test('/tmp/system-probe/head', pkg, head_results_path)
      }

      regressions = {}
      Open3.popen2e("sudo", "-E", "/tmp/system-probe/benchstat", main_results_path, head_results_path) do |_, output, wait_thr|
        header_line = nil
        section_headers = nil
        output.each_line do |line|
          puts line
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
            if !regressions.has_key?(header_line) then
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
