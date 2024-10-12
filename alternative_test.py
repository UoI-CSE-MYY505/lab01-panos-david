import subprocess
import sys
import re


MATRIC_NUMBER = 5479


expected_registers = {
    's0': MATRIC_NUMBER,
    's1': MATRIC_NUMBER + 1,
    's2': -1 & 0xFFFFFFFF,
    's3': 0xFF,
    't1': None,
}

expected_memory = {
}

def assemble_code():
    """Assemble the lab01.s file into an executable."""
    assemble_cmd = ['riscv64-unknown-elf-as', '-o', 'lab01.o', 'lab01.s']
    link_cmd = ['riscv64-unknown-elf-ld', '-o', 'lab01', 'lab01.o']
    try:
        subprocess.check_call(assemble_cmd)
        subprocess.check_call(link_cmd)
    except subprocess.CalledProcessError as e:
        print(f"Error during assembly/linking: {e}")
        sys.exit(1)

def run_spike():
    """Run the executable in Spike simulator with GDB."""
    spike_cmd = ['spike', '--gdb-port=1234', 'lab01']
    spike_process = subprocess.Popen(spike_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return spike_process

def run_gdb():
    """Use GDB to connect to Spike and inspect registers and memory."""
    gdb_cmds = '''
    target remote localhost:1234
    break exit
    continue
    info registers s0 s1 s2 s3 t1 a2
    x/10wx a2
    quit
    '''
    gdb_process = subprocess.run(
        ['riscv64-unknown-elf-gdb', 'lab01'],
        input=gdb_cmds,
        text=True,
        capture_output=True
    )
    return gdb_process.stdout

def parse_gdb_output(output):
    """Parse GDB output to extract register and memory values."""
    registers = {}
    memory = {}
    lines = output.splitlines()

    reg_pattern = re.compile(r'\s*(\w+)\s+0x([0-9a-fA-F]+)')
    for line in lines:
        match = reg_pattern.match(line)
        if match:
            reg_name = match.group(1)
            reg_value = int(match.group(2), 16)
            registers[reg_name] = reg_value

    mem_pattern = re.compile(r'0x([0-9a-fA-F]+):\s+((?:0x[0-9a-fA-F]+\s+)+)')
    for line in lines:
        match = mem_pattern.match(line)
        if match:
            address = int(match.group(1), 16)
            data = match.group(2).split()
            for i, word in enumerate(data):
                mem_addr = address + i * 4
                mem_value = int(word, 16)
                memory[mem_addr] = mem_value

    return registers, memory

def main():
    assemble_code()
    spike_process = run_spike()
    gdb_output = run_gdb()

    spike_process.terminate()

    registers, memory = parse_gdb_output(gdb_output)

    expected_registers['t1'] = registers['a2'] + 0x10
    expected_memory[registers['a2'] + 12] = MATRIC_NUMBER

    print("Checking register values...")
    for reg, expected_value in expected_registers.items():
        actual_value = registers.get(reg)
        if actual_value != expected_value:
            print(f"Register {reg} mismatch: expected {expected_value}, got {actual_value}")
        else:
            print(f"Register {reg} OK: {actual_value}")

    print("\nChecking memory values...")
    for addr, expected_value in expected_memory.items():
        actual_value = memory.get(addr)
        if actual_value != expected_value:
            print(f"Memory at 0x{addr:X} mismatch: expected {expected_value}, got {actual_value}")
        else:
            print(f"Memory at 0x{addr:X} OK: {actual_value}")

if __name__ == '__main__':
    main()
