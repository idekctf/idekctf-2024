#!/bin/python3
from auto_chall import generate
import subprocess
import random
import base64
import string
import sys
import os


def welcome():
    print(
        f"Hello and welcome to this serie of automated pwn challenges !\n"
        f"This is the level one, it mainly serves as an introduction to automation\n"
        f"You will be required to solve 50 challenges in row. To do so, you will be "
        f"provided a binary encoded in base64, and it will wait for a valid exploit "
        f"encoded in base64 for 30 seconds.\nFor this level, you are only expected "
        f"to call the win function. Good luck!"
    )


def send_binary():
    filename = "".join(random.choices(string.ascii_lowercase, k=10))
    result, secret, path, tempdir, secret_path = generate(filename=filename)
    if not result:
        print(
            "Something went wrong during generation of a challenge. Please contact and admin"
        )
        return Exception(f"Error during generation!\n{result}"), None, None

    with open(path, "rb") as f:
        binary = f.read()
        b64_binary = base64.b64encode(binary)
        print(f"----------------")
        print(b64_binary.decode())
        print(f"----------------")

    return path, secret, tempdir, secret_path


def clean_binary(tempdir, secret_path):
    tempdir.cleanup()
    secret_path.cleanup()
    return


def verify_solve(path: str, secret: str):
    solve = input("Provide your solution:\n")
    try:
        solve = base64.b64decode(solve)
    except Exception as e:
        print(e)
        print("Invalid base64! Bye.")
        return False

    command = [path]
    result = b"failed"
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = process.communicate(input=solve)
        result = stdout + stderr
    except subprocess.CalledProcessError as e:
        if secret in result.decode():
            return True
        return False

    try:
        if secret in result.decode():
            return True
        return False
    except Exception as e:
        print(f"[ERROR] something went really wrong, please contact an admin: {e}")
        return False


def main():
    welcome()
    for i in range(50):
        path, secret, tempdir, secret_path = send_binary()
        success = verify_solve(path, secret)
        if success != True:
            print(f"You failed! Better luck next time.")
            clean_binary(tempdir, secret_path)
            exit(-1)

        clean_binary(tempdir, secret_path)

    print(f"Congrats !!! You made it. Here is your flag:")
    print(f"idek{{automation_is_fun_but_it_could_be_funnier_by_being_harder}}")
    exit(0)


if __name__ == "__main__":
    main()
