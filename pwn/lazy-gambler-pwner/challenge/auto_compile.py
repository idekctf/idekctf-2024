import subprocess
import os


class CCompiler:
    def __init__(self, source_file="code.c", output_file="code"):
        self.source_file = source_file
        self.output_file = output_file

    def compile_c_code(self):
        compile_command = [
            "gcc",
            self.source_file,
            "-o",
            self.output_file,
            "-no-pie",
            "-O0",
            "-fno-stack-protector",
            "-Wall",
            "-Wextra",
            "-pedantic",
            "-std=c11",
        ]
        result = subprocess.run(compile_command, capture_output=True, text=True)
        if result.returncode != 0:
            print("[ERROR] Compilation failed. Please contact an admin.")
            return False

        result = self._prepare_binary()
        if result.returncode != 0:
            print("[ERROR] Binary preparation failed. Please contact an admin.")
            return False

        return True

    def _prepare_binary(self):
        compile_command = ["strip", "-s", self.output_file]
        return subprocess.run(compile_command, capture_output=True, text=True)
