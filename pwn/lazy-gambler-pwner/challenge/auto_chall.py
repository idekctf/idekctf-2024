from auto_codegen import CGen
from auto_compile import CCompiler


import tempfile
import os


def generate(filename: str):
    c_code_generator = CGen()
    c_code = repr(c_code_generator)
    secret = c_code_generator.get_secret()
    secret_path = c_code_generator.get_tempdir()

    tempdir = tempfile.TemporaryDirectory()
    c_source_path = os.path.join(tempdir.name, f"{filename}.c")

    with open(c_source_path, "w") as c_file:
        c_file.write(c_code)

    output_bin_path = os.path.join(tempdir.name, f"{filename}.bin")

    compiler = CCompiler(source_file=c_source_path, output_file=output_bin_path)
    compilation_success = compiler.compile_c_code()

    # This is so ugly I want to die
    if compilation_success:
        return True, secret, output_bin_path, tempdir, secret_path
    return False, None, None, None, None



if __name__ == "__main__":
    generate()
