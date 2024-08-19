from auto_vuln_func import VulnFunctionGenerator
from auto_win_func import WinFunctionGenerator
import random
import string


class CGen:
    def __init__(self):
        self.secret = None
        self.tempdir = None
        self.num_functions = random.randint(25, 30)  # Generate 25 to 30 functions
        self.vuln_func = random.randint(0, self.num_functions - 1)
        self.win_func = random.randint(0, self.num_functions - 1)
        while self.win_func == self.vuln_func:
            self.win_func = random.randint(0, self.num_functions - 1)
        self.function_graph = {i: set() for i in range(self.num_functions)}
        self.unique_id = 0
        self.functions = [
            self._generate_random_function(i) for i in range(self.num_functions)
        ]
        self.main_function = self._generate_main_function()
        self.ensure_all_functions_used()
        self.ensure_winnable_path()

    def _generate_random_string(self, length=7):
        return "".join(random.choices(string.ascii_lowercase, k=length))

    def _generate_xor_string(self, text):
        key = random.randint(1, 255)
        obfuscated = ",".join(str(ord(c) ^ key) for c in text)
        return key, obfuscated

    def _generate_xor_code(self, obfuscated, key):
        unique_id = self.unique_id
        self.unique_id += 1
        length = len(obfuscated.split(","))
        return (
            f"    char decoded_{unique_id}[{length + 1}];\n"
            f"    int encoded_{unique_id}[] = {{{obfuscated}}};\n"
            f"    for(int i = 0; i < {length}; i++) {{\n"
            f"        decoded_{unique_id}[i] = encoded_{unique_id}[i] ^ {key};\n"
            f"    }}\n"
            f"    decoded_{unique_id}[{length}] = '\\0';\n"
        ), f"decoded_{unique_id}"

    def _generate_question_branch(self, index):
        num_solutions = random.randint(2, 5)  # Random number of solutions (2 to 5)
        target_funcs = [
            random.randint(0, self.num_functions - 1) for _ in range(num_solutions)
        ]
        answer_strings = [self._generate_random_string() for _ in range(num_solutions)]

        question = '    printf("Choose '
        if random.choice(
            [False, False, True, False]
        ):  # Apply XOR obfuscation sometimes
            key, obfuscated = self._generate_xor_string(" or ".join(answer_strings))
            xor_code, xor_var = self._generate_xor_code(obfuscated, key)
            question += '");\n\n' + xor_code + f'\n    printf("%s?\\n", {xor_var});\n'
        else:
            question += f'{" or ".join(answer_strings)}?\\n");\n'

        answer = f'    char choice[20];\n    scanf("%{random.randint(14, 19)}s", choice);\n    getchar();\n\n'

        branches = ""
        for solution, func in zip(answer_strings, target_funcs):
            if random.choice(
                [False, False, True, False]
            ):  # Apply XOR obfuscation sometimes
                key, obfuscated = self._generate_xor_string(solution)
                xor_code, xor_var = self._generate_xor_code(obfuscated, key)
                self.function_graph[index].add(func)
                branches += (
                    f"{{}}\n\n"
                    + xor_code
                    + f"    if (strcmp(choice, {xor_var}) == 0) {{\n"
                    f"        return func_{func}();\n"
                    f"    }} else "
                )
            else:
                branches += (
                    f'    if (strcmp(choice, "{solution}") == 0) {{\n'
                    f"        return func_{func}();\n"
                    f"    }} else "
                )
        branches += '{\n        printf("Invalid choice. Sad.\\n");\n    }\n\n'

        end = f"    return 0;"

        return question + answer + branches + end

    def _generate_random_function(self, index):
        function_name = f"func_{index}"
        branches = []

        if index == self.vuln_func:
            vuln = VulnFunctionGenerator()
            branches.append(repr(vuln))
        elif index == self.win_func:
            win = WinFunctionGenerator()
            branches.append(repr(win))
            self.secret = win.get_secret()
            self.tempdir = win.get_tempdir()
        else:
            branches.append(self._generate_question_branch(index))

        function_body = "\n".join(branches)
        return f"int {function_name}() {{\n{function_body}\n}}"

    def _generate_main_function(self):
        start_func = random.randint(0, self.num_functions - 1)
        self.function_graph[-1] = {start_func}  # Add main function's connection
        return f"int main() {{\n    func_{start_func}();\n    exit(0);\n}}"

    def _generate_headers(self):
        headers = [
            "#include <stdio.h>",
            "#include <stdlib.h>",
            "#include <string.h>",
        ]
        return "\n".join(headers)

    def generate_c_code(self):
        headers = self._generate_headers()
        decls = "\n".join([f"int func_{i}();" for i in range(self.num_functions)])
        functions = "\n\n".join(self.functions)
        return headers + "\n" + decls + "\n\n" + functions + "\n\n" + self.main_function

    def __repr__(self):
        return self.generate_c_code()

    def ensure_winnable_path(self):
        visited = set()
        self._dfs(0, visited)
        if self.vuln_func not in visited:
            path = self._create_path_to_win_func(0)
            for i in range(len(path) - 1):
                self._connect_functions(path[i], path[i + 1])

    def _dfs(self, node, visited):
        if node in visited:
            return
        visited.add(node)
        for neighbor in self.function_graph[node]:
            self._dfs(neighbor, visited)

    def _create_path_to_win_func(self, start):
        path = [start]
        current = start
        while current != self.vuln_func:
            next_func = random.choice(list(set(range(self.num_functions)) - set(path)))
            path.append(next_func)
            current = next_func
        return path

    def _connect_functions(self, func_from, func_to):
        self.function_graph[func_from].add(func_to)
        self.functions[func_from] = self._replace_last_branch_with_win_path(
            self.functions[func_from], func_to
        )

    def _replace_last_branch_with_win_path(self, func_body, target_func):
        split_body = func_body.rsplit("}", 1)
        if len(split_body) < 2:
            return func_body

        return split_body[0] + f"    return func_{target_func}();\n" + "}"

    def ensure_all_functions_used(self):
        unused_funcs = set(range(self.num_functions)) - set(self.function_graph.keys())
        for func in unused_funcs:
            random_func = random.randint(0, self.num_functions - 1)
            self.function_graph[random_func].add(func)
            self.functions[random_func] = self._replace_last_branch_with_win_path(
                self.functions[random_func], func
            )

    def get_secret(self):
        return self.secret

    def get_tempdir(self):
        return self.tempdir
