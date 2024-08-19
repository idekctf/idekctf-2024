import random
import string
import hashlib
import tempfile
import os


class WinFunctionGenerator:
    def __init__(self):
        self.win_functions = [
            self.win_system_cat,
            self.win_system_execve,
        ]
        self.tempdir = None
        self.secret = None

    def generate_secret(self, length=10):
        key = "".join(random.choices(string.ascii_lowercase, k=length))
        return hashlib.md5(key.encode()).digest().hex()

    def generate_file(self, length=7):
        """Generate a random string of fixed length."""
        self.tempdir = tempfile.TemporaryDirectory()
        filename = random.choice(["flag", "pass", "winkey", "secret", "winkey"])
        path = os.path.join(self.tempdir.name, filename)
        self.secret = self.generate_secret()
        with open(path, "w") as f:
            f.write(self.secret)
        return path

    def generate_win_function(self):
        """Select and call one of the win functions randomly."""
        func_generator = random.choice(self.win_functions)
        return func_generator()

    def win_system_cat(self):
        file_name = self.generate_file()
        code = (
            f'    char *cmd = "cat {file_name}";\n'
            f"    system(cmd);\n"
            f"    return 0;\n"
        )
        return code

    def win_system_execve(self):
        file_name = self.generate_file()
        code = (
            f'    char *args[] = {{"/bin/cat", "{file_name}", NULL}};\n'
            f"    execve(args[0], args, NULL);\n"
            f"    return 0;\n"
        )
        return code

    def win_fopen_fgets_print(self):
        file_name = self.generate_file()
        code = (
            f'    FILE *file = fopen("{file_name}", "r");\n'
            f"    if (file != NULL) {{\n"
            f"        char buffer[1024];\n"
            f"        fgets(buffer, sizeof(buffer), file);\n"
            f'        printf("%s", buffer);\n'
            f"        fclose(file);\n"
            f"    }}\n"
            f"    return 0;\n"
        )
        return code

    def win_fopen_fread_print(self):
        file_name = self.generate_file()
        code = (
            f'    FILE *file = fopen("{file_name}", "r");\n'
            f"    if (file != NULL) {{\n"
            f"        char buffer[1024];\n"
            f"        size_t bytes_read = fread(buffer, 1, sizeof(buffer), file);\n"
            f"        if (bytes_read > 0) {{\n"
            f'            printf("%s", buffer);\n'
            f"        }}\n"
            f"        fclose(file);\n"
            f"    }}\n"
            f"    return 0;\n"
        )
        return code

    def get_secret(self):
        return self.secret

    def get_tempdir(self):
        return self.tempdir
    
    def __repr__(self):
        return self.generate_win_function()
