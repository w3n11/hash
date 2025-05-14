from argparse import ArgumentParser, RawTextHelpFormatter
from threading import Lock
from hashlib import (
    sha1,
    sha224,
    sha256,
    sha384,
    sha512,
    sha3_224,
    sha3_256,
    sha3_384,
    sha3_512
)
from sys import exit, stderr, stdout
from pathlib import Path
from typing import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import TextIOWrapper


output_lock = Lock()

parser = ArgumentParser(
    description="Custom hash calculating command. Author: Marek Pucher",
    formatter_class=RawTextHelpFormatter
    )

parser.add_argument("filepath",
                    help="Path to a file or directory\n"
                         "If directory, it will recursively compute the hashes"
                         " for all files and directories inside the directory")

parser.add_argument("--alg",
                    help="The algorithm to calculate hash (default: sha256)\n"
                         "  - sha1\n"
                         "  - sha224\n"
                         "  - sha256\n"
                         "  - sha384\n"
                         "  - sha512\n"
                         "  - sha3_224\n"
                         "  - sha3_256\n"
                         "  - sha3_384\n"
                         "  - sha3_512",
                    default="sha256")

parser.add_argument("--comp",
                    help="Hash to compare with",
                    default=None)

parser.add_argument("--threads",
                    type=int,
                    default=1,
                    help="Number of threads to use for hashing (default: 1)\n"
                         "Useful for directories with large amount of files")

parser.add_argument("--output",
                    help="Redirects the output to a specifed file",
                    default=None)

args = parser.parse_args()
OUTPUT_FILE = open(args.output, "w",
                   encoding="utf-8") if args.output else stdout
stdout = TextIOWrapper(stdout.buffer, encoding="utf-8")


def mb_to_bytes(megabytes: int) -> int:
    return megabytes * pow(2, 20)


def gather_files(dirpath: str) -> list[str]:
    files = []
    for item in Path(dirpath).rglob('*'):
        if item.is_file():
            files.append(item.as_posix())
    return files


def process_dir(hash_func: Callable, dirpath: str) -> None:
    dir_path: Path = Path(dirpath)
    for item in dir_path.iterdir():
        if item.is_dir():
            process_dir(hash_func, item.as_posix())
        else:
            calculate_hash(hash_func, item.as_posix(), True)


def process_dir_threaded(hash_func: Callable, dirpath:
                         str, max_workers: int = 1) -> None:
    files = gather_files(dirpath)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(calculate_hash, hash_func, filepath, True,
                            stdout == OUTPUT_FILE and max_workers == 1)
            for filepath in files
        ]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"Error hashing file: {e}", file=stderr)


def calculate_hash(hash_func: Callable, filepath: str,
                   print_filename: bool = False,
                   print_progress: bool = True) -> None:
    file_size: int = 0
    try:
        with open(file=filepath, mode="rb") as f:
            file_size = Path(filepath).stat().st_size
            hasher = hash_func()
            bytes_read = 0
            chunk_size = mb_to_bytes(32)
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
                bytes_read += len(chunk)
                if file_size > mb_to_bytes(512) and args.comp is None and (
                        print_progress):
                    percent = (bytes_read / file_size) * 100
                    print(f"\rProgress: {percent:.2f}% ", end="", flush=True)
    except FileNotFoundError:
        print(f"Error: File '{filepath}' not found.", file=stderr)
        exit(1)
    except PermissionError:
        print(f"Skipping inaccessible file: '{filepath}'", file=stderr)
        return
    calculated_hash: str = hasher.hexdigest()
    if file_size > mb_to_bytes(512) and args.comp is None and (
            print_progress):
        print("\r" + " " * 40 + "\r", end="", flush=True)
    if print_filename:
        if args.comp is None:
            with output_lock:
                print(f"{calculated_hash}\t{filepath}", file=OUTPUT_FILE)
        else:
            if args.comp == calculated_hash:
                print(filepath, file=OUTPUT_FILE)
                exit(0)
    else:
        if args.comp is None:
            with output_lock:
                print(calculated_hash, file=OUTPUT_FILE)
        else:
            print(args.comp, file=OUTPUT_FILE)
            exit(1)


def main():
    hash_func: Callable | None = None
    algorithms = {
        "sha1": sha1,
        "sha224": sha224,
        "sha256": sha256,
        "sha384": sha384,
        "sha512": sha512,
        "sha3_224": sha3_224,
        "sha3_256": sha3_256,
        "sha3_384": sha3_384,
        "sha3_512": sha3_512
    }

    alg_name = args.alg.lower()
    if alg_name not in algorithms:
        print(f"Error: Unknown algorithm '{args.alg}'", file=stderr)
        exit(1)

    if hash_func is None:
        hash_func = algorithms[alg_name]
    file_path = Path(args.filepath)
    if file_path.is_dir():
        process_dir_threaded(hash_func, file_path.as_posix(), args.threads)
    else:
        calculate_hash(hash_func, file_path.as_posix())
    if OUTPUT_FILE is not stdout:
        OUTPUT_FILE.close()


if __name__ == "__main__":
    main()
