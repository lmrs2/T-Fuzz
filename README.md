# T-Fuzz

T-Fuzz consists of 2 components:
- Fuzzing tool (TFuzz): a fuzzing tool based on program transformation
- Crash Analyzer (CrashAnalyzer): a tool that verifies whether crashes found transformed
  programs are true bugs in the original program or not (coming soon).


To see the original installation procedure, see [T-Fuzz official repo](https://github.com/HexHive/T-Fuzz).

## Installation for python-3.5 and Ubuntu 14.04 x64

```
# angr/fuzzer/etc
$ sudo apt-get install software-properties-common
$ sudo add-apt-repository ppa:deadsnakes/ppa
$ sudo apt-get update
$ sudo apt-get install python3.5-dev libffi-dev build-essential virtualenvwrapper
$ mkvirtualenv --python=$(which python3.5) tfuzz-env # now we're in the env

$ pip install --upgrade pip
$ pip install --upgrade setuptools
$ UNICORN_QEMU_FLAGS="--python=/usr/bin/python2.7" pip install unicorn
$ python -m pip install angr

$ sudo apt-get install build-essential gcc-multilib debootstrap debian-archive-keyring libtool # automake, autoconf already installed
$ sudo apt-get build-dep qemu
$ pip install git+https://github.com/shellphish/shellphish-afl
$ pip install git+https://github.com/shellphish/fuzzer

# T-Fuzz
$ pip install subprocess32 r2pipe intervaltree
$ git clone https://github.com/radare/radare2.git
$ cd radare2 && sys/user.sh && cd -
# TODO: add $HOME/bin to your PATH, e.g., .bashrc
$ git clone git@github.sisa.samsung.com:KnoxSecurity/TFuzz.git
$ cd T-Fuzz
```

# Fuzzing target programs with T-Fuzz

```
# first instrument the program/binary. Note: angr may be installed somewhere else?
$ AFL_CC=`llvm-config-XX --bindir`/clang ~/.virtualenvs/angr/bin/afl-unix/afl-clang <program> -o <program>.afl

# then fuzz, example (@@ indicates input file like for AFL):
$ ./TFuzzLauncher  --program <program.afl> --work_dir <work_dir> --target_opts "-d @@"
```

Where
- <program.afl>: the path to the target program to fuzz
- <work_dir>: the directory to save the results
- <target_opts>: the options to pass to the target program, like AFL, use `@@` as
  		 placeholder for files to mutate.


## Examples

1. Fuzzing base64 with T-Fuzz

```
$ ./TFuzzLauncher  --program  target_programs/base64  --work_dir workdir_base64 --target_opts "-d @@"
```

2. Fuzzing uniq with T-Fuzz

```
$ ./TFuzzLauncher  --program  target_programs/uniq  --work_dir workdir_uniq --target_opts "@@"
```

3. Fuzzing md5sum with T-Fuzz

```
$ ./TFuzzLauncher  --program  target_programs/md5sum  --work_dir workdir_md5sum --target_opts "-c @@"
```

4. Fuzzing who with T-Fuzz

```
$ ./TFuzzLauncher  --program  target_programs/who  --work_dir workdir_who --target_opts "@@"
```

# Using CrashAnalyzer to verify crashes

T-Fuzz CrashAnalyzer has been put in a docker image, however,
it is still not working in all binaries we tested, we are still investigating
it the cause.

Here is how:

Run the following command to run our docker image

```
$ [sudo] docker pull tfuzz/tfuzz-test
$ [sudo] docker run  --security-opt seccomp:unconfined -it tfuzz/tfuzz-test  /usr/bin/zsh 
```

In the container:

There are 3 directories:
- `release`: contains code the built lava binaries
- `results`: contains some results we found in lava-m dataset 
- `radare2`: it is a program used by T-Fuzz.


Currently, `T-Fuzz` may not work, because the tracer crashes accidentally.
And the CrashAnalyzer can not work on all results.
But some cases can be recovered.

For example:


To verify bugs in base64, first goto `release` and checkout ca_base64:

```
$ cd release
$ git checkout ca_base64
```

Then we use a transformed program to recover the crash in the original program:

1. Choose a transformed program and run it on the input found by a fuzzer:

```
$ cd ~
$./results/ca_base64/554/base64_tfuzz_28/base64_tfuzz_28 -d ./results/ca_base64/554/crashing_inputs_from/results_saved_0_from 
[1]    131 segmentation fault (core dumped)  ./results/ca_base64/554/base64_tfuzz_28/base64_tfuzz_28 -d
```


2. Recover an input from this transformed program and crashing input

```
$ ./release/CrashAnalyzer  --tprogram ./results/ca_base64/554/base64_tfuzz_28/base64_tfuzz_28 --target_opts "-d @@" --crash_input ./results/ca_base64/554/crashing_inputs_from/results_saved_0_from --result_dir base64_result --save_to recover
WARNING | 2018-12-04 04:28:22,350 | angr.analyses.disassembly_utils | Your verison of capstone does not support MIPS instruction groups.
Trying /root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from
WARNING | 2018-12-04 04:28:23,228 | angr.project | Address is already hooked, during hook(0x9021cd0, <SimProcedure ReturnUnconstrained>). Re-hooking.
WARNING | 2018-12-04 04:28:23,228 | angr.project | Address is already hooked, during hook(0x90dd000, <SimProcedure ReturnUnconstrained>). Re-hooking.
WARNING | 2018-12-04 04:28:23,229 | angr.simos.linux | Tracer has been heavily tested only for CGC. If you find it buggy for Linux binaries, we are sorry!
Adding <Bool Or(((file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_0_0_8 >= 65) && (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_0_0_8 <= 90)), ((file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_0_0_8 >= 97) && (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_0_0_8 <= 122)), ((file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_0_0_8 >= 48) && (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_0_0_8 <= 57)), (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_0_0_8 == 43), (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_0_0_8 == 47))>
Adding <Bool Or(((file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_1_1_8 >= 65) && (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_1_1_8 <= 90)), ((file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_1_1_8 >= 97) && (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_1_1_8 <= 122)), ((file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_1_1_8 >= 48) && (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_1_1_8 <= 57)), (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_1_1_8 == 43), (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_1_1_8 == 47))>
Adding <Bool Or(((file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_2_2_8 >= 65) && (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_2_2_8 <= 90)), ((file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_2_2_8 >= 97) && (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_2_2_8 <= 122)), ((file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_2_2_8 >= 48) && (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_2_2_8 <= 57)), (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_2_2_8 == 43), (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_2_2_8 == 47))>
Adding <Bool Or(((file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_3_3_8 >= 65) && (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_3_3_8 <= 90)), ((file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_3_3_8 >= 97) && (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_3_3_8 <= 122)), ((file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_3_3_8 >= 48) && (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_3_3_8 <= 57)), (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_3_3_8 == 43), (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_3_3_8 == 47))>
results saved to /root/base64_result/recover_0
```

Then `/root/base64_result/recover_0` is generated, we can use it to trigger a crash in the original program.

3. verify the input by running the generated  input on the original program

```
$ ./results/base64 -d base64_result/recover_0 
Successfully triggered bug 554, crashing now!
Successfully triggered bug 554, crashing now!
Successfully triggered bug 554, crashing now!
[1]    177 segmentation fault (core dumped)  ./results/base64 -d base64_result/recover_0
```