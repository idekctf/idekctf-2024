import random
import string


class VulnFunctionGenerator:
    def __init__(self):
        self.vulnerable_functions = [
            self.generate_gets_vuln,
            self.generate_fgets_vuln,
        ]

    def generate_random_string(self, length=7):
        return "".join(random.choices(string.ascii_lowercase, k=length))

    def generate_gets_vuln(self):
        buffer_size = random.randint(10, 50)
        func_name = self.generate_random_string()
        code = (
            f"    char buffer[{buffer_size}];\n"
            f"    gets(buffer);\n"
            f"    return 0;\n"
        )
        return code

    def generate_fgets_vuln(self):
        buffer_size = random.randint(10, 50)
        vuln_size = buffer_size + random.randint(80, 100)
        func_name = self.generate_random_string()
        code = (
            f"    char buffer[{buffer_size}];\n"
            f"    fgets(buffer, {vuln_size}, stdin);\n"
            f"    return 0;\n"
        )
        return code

    def generate_vulnerable_function(self):
        func_generator = random.choice(self.vulnerable_functions)
        return func_generator()

    def __repr__(self):
        return self.generate_vulnerable_function()
