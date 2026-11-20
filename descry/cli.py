from __future__ import annotations

import argparse
import os
import sys
from typing import Callable, Optional, Sequence

from descry import io as input_output
from descry import output
from descry.ciphers import caesar, vigenere, xor
from descry.encodings import decode as encodings
from descry.encodings import detect
from descry.scoring import (
    Result,
    confidence,
    dedupe_results,
    frequency_rows,
    frequency_summary,
    rank_results,
)

EXAMPLES = """Examples:
  echo "Khoor Zruog" | descry crack
  descry vigenere crack -f cipher.txt --top 3
  descry decode "NjU2YzZjNmY="
"""


class CliError(Exception):
    pass


class DescryParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CliError(
            f"{message}\n       run 'descry -h' for usage and examples"
        )


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a whole number") from error
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def shift_value(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "shift must be a whole number from 0 to 25"
        ) from error
    if not 0 <= parsed <= 25:
        raise argparse.ArgumentTypeError(
            "shift must be between 0 and 25; try --shift 3"
        )
    return parsed


def threshold_value(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("threshold must be a number") from error
    if not 0.0 <= parsed <= 100.0:
        raise argparse.ArgumentTypeError(
            "threshold must be between 0 and 100"
        )
    return parsed


def add_input(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "text",
        nargs="?",
        metavar="TEXT",
        help="input text; omit to read stdin",
    )
    parser.add_argument(
        "-f",
        "--file",
        metavar="FILE",
        help="read input from FILE",
    )


def add_output(
    parser: argparse.ArgumentParser,
    top_enabled: bool = False,
    top_default: Optional[int] = None,
    threshold: Optional[float] = None,
) -> None:
    parser.add_argument(
        "--format",
        choices=("pretty", "plain", "json"),
        default=None,
        help="output format (default: pretty on a terminal, plain when piped)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI color",
    )
    if top_enabled:
        hint = f"default: {top_default}" if top_default is not None else "default: all"
        parser.add_argument(
            "--top",
            type=positive_int,
            default=top_default,
            metavar="N",
            help=f"show at most N results ({hint})",
        )
    if threshold is not None:
        parser.add_argument(
            "--threshold",
            type=threshold_value,
            default=threshold,
            metavar="PCT",
            help=f"exit 1 if the best result is below PCT (default: {threshold:g})",
        )


def add_leaf(
    subparsers: argparse._SubParsersAction,
    name: str,
    description: str,
    examples: str,
    handler: Callable[[argparse.Namespace], int],
) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(
        name,
        help=description,
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples,
    )
    parser.set_defaults(handler=handler)
    return parser


def build_parser() -> argparse.ArgumentParser:
    parser = DescryParser(
        prog="descry",
        description="Cipher analysis and cracking for CTFs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EXAMPLES,
    )
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    crack = add_leaf(
        subparsers,
        "crack",
        "Auto-detect and crack the input; prints ranked plaintext candidates.",
        """Examples:
  echo "Khoor Zruog" | descry crack
  descry crack "Wklv vhfuhw phvvdjh" --top 3
  descry crack -f cipher.txt --format json
""",
        handle_crack,
    )
    add_input(crack)
    add_output(crack, top_enabled=True, top_default=6, threshold=45.0)

    identify = add_leaf(
        subparsers,
        "id",
        "Identify an encoding or cipher with confidence.",
        """Examples:
  descry id "SGVsbG8gd29ybGQ="
  descry id "Khoor Zruog"
  echo "01001000 01101001" | descry id
""",
        handle_id,
    )
    add_input(identify)
    add_output(identify, top_enabled=True, top_default=8, threshold=30.0)

    caesar_parser = subparsers.add_parser(
        "caesar",
        help="Caesar shift: encrypt, decrypt, brute force",
        description="Caesar shift cipher: encrypt, decrypt, or brute force.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  descry caesar enc "Hello World" --shift 3
  descry caesar dec "Khoor Zruog" --shift 3
  descry caesar brute "Khoor Zruog" --top 5
""",
    )
    caesar_parser.set_defaults(handler=handle_help_request, group_parser=caesar_parser)
    caesar_subparsers = caesar_parser.add_subparsers(dest="action", metavar="ACTION")

    caesar_enc = add_leaf(
        caesar_subparsers,
        "enc",
        "Encrypt with a Caesar shift from 0 to 25.",
        """Examples:
  descry caesar enc "Hello World" --shift 3
  echo "Attack at dawn" | descry caesar enc --shift 7
""",
        handle_caesar_enc,
    )
    add_input(caesar_enc)
    caesar_enc.add_argument(
        "--shift", type=shift_value, required=True, metavar="N", help="shift from 0 to 25"
    )
    add_output(caesar_enc)

    caesar_dec = add_leaf(
        caesar_subparsers,
        "dec",
        "Decrypt with a known Caesar shift from 0 to 25.",
        """Examples:
  descry caesar dec "Khoor Zruog" --shift 3
  descry caesar dec -f cipher.txt --shift 13
""",
        handle_caesar_dec,
    )
    add_input(caesar_dec)
    caesar_dec.add_argument(
        "--shift", type=shift_value, required=True, metavar="N", help="shift from 0 to 25"
    )
    add_output(caesar_dec)

    caesar_brute = add_leaf(
        caesar_subparsers,
        "brute",
        "Try all 26 shifts and rank them by English likelihood.",
        """Examples:
  descry caesar brute "Khoor Zruog"
  echo "Wklv vhfuhw" | descry caesar brute --top 5
""",
        handle_caesar_brute,
    )
    add_input(caesar_brute)
    add_output(caesar_brute, top_enabled=True, top_default=None, threshold=45.0)

    vigenere_parser = subparsers.add_parser(
        "vigenere",
        help="Vigenere: encrypt, decrypt, crack",
        description="Vigenere cipher: encrypt, decrypt, or crack.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  descry vigenere enc "Attack at dawn" --key LEMON
  descry vigenere dec "Lxfopv ef rnhr" --key LEMON
  descry vigenere crack -f cipher.txt --top 3
""",
    )
    vigenere_parser.set_defaults(
        handler=handle_help_request, group_parser=vigenere_parser
    )
    vigenere_subparsers = vigenere_parser.add_subparsers(
        dest="action", metavar="ACTION"
    )

    vigenere_enc = add_leaf(
        vigenere_subparsers,
        "enc",
        "Encrypt with a Vigenere key.",
        """Examples:
  descry vigenere enc "Attack at dawn" --key LEMON
  echo "Meet me at noon" | descry vigenere enc --key KEY
""",
        handle_vigenere_enc,
    )
    add_input(vigenere_enc)
    vigenere_enc.add_argument(
        "--key", required=True, metavar="KEY", help="letters-only key"
    )
    add_output(vigenere_enc)

    vigenere_dec = add_leaf(
        vigenere_subparsers,
        "dec",
        "Decrypt with a Vigenere key.",
        """Examples:
  descry vigenere dec "Lxfopv ef rnhr" --key LEMON
  descry vigenere dec -f cipher.txt --key SECRET
""",
        handle_vigenere_dec,
    )
    add_input(vigenere_dec)
    vigenere_dec.add_argument(
        "--key", required=True, metavar="KEY", help="letters-only key"
    )
    add_output(vigenere_dec)

    vigenere_crack = add_leaf(
        vigenere_subparsers,
        "crack",
        "Find the key length with index of coincidence and Kasiski, then recover the key.",
        """Examples:
  descry vigenere crack "Lxfopv ef rnhr" --max-key-length 12
  descry vigenere crack -f cipher.txt --top 3
""",
        handle_vigenere_crack,
    )
    add_input(vigenere_crack)
    vigenere_crack.add_argument(
        "--max-key-length",
        type=positive_int,
        default=20,
        metavar="N",
        help="largest key length to test (default: 20)",
    )
    add_output(vigenere_crack, top_enabled=True, top_default=5, threshold=45.0)

    xor_parser = subparsers.add_parser(
        "xor",
        help="XOR: encrypt, decrypt, crack",
        description="XOR cipher: encrypt, decrypt, single-byte and repeating-key cracking.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  descry xor enc "secret" --key key
  descry xor dec "1b1e1d1e1f" --key key
  descry xor crack "1b0c1e0d" --max-key-length 16
""",
    )
    xor_parser.set_defaults(handler=handle_help_request, group_parser=xor_parser)
    xor_subparsers = xor_parser.add_subparsers(dest="action", metavar="ACTION")

    xor_enc = add_leaf(
        xor_subparsers,
        "enc",
        "Encrypt bytes with an XOR key; prints lowercase hex.",
        """Examples:
  descry xor enc "secret" --key key
  descry xor enc "secret" --hex-key 2a
""",
        handle_xor_enc,
    )
    add_input(xor_enc)
    xor_enc.add_argument("--key", required=True, metavar="KEY", help="key text")
    xor_enc.add_argument(
        "--hex-key", action="store_true", help="interpret KEY as hex bytes"
    )
    xor_enc.add_argument(
        "--hex-input", action="store_true", help="interpret TEXT as hex bytes"
    )
    add_output(xor_enc)

    xor_dec = add_leaf(
        xor_subparsers,
        "dec",
        "Decrypt hex or raw bytes with an XOR key.",
        """Examples:
  descry xor dec "1b1e1d1e1f" --key key
  descry xor dec "1b1e1d1e1f" --hex-key 2a --hex-output
""",
        handle_xor_dec,
    )
    add_input(xor_dec)
    xor_dec.add_argument("--key", required=True, metavar="KEY", help="key text")
    xor_dec.add_argument(
        "--hex-key", action="store_true", help="interpret KEY as hex bytes"
    )
    xor_dec.add_argument(
        "--raw-input", action="store_true", help="treat TEXT as raw text, not hex"
    )
    xor_dec.add_argument(
        "--hex-output", action="store_true", help="print lowercase hex instead of text"
    )
    add_output(xor_dec)

    xor_crack = add_leaf(
        xor_subparsers,
        "crack",
        "Crack single-byte XOR, or repeating-key XOR with Hamming distance.",
        """Examples:
  descry xor crack "1b0c1e0d"
  descry xor crack -f cipher.bin --repeating --max-key-length 16
  echo "1b0c1e0d" | descry xor crack --single
""",
        handle_xor_crack,
    )
    add_input(xor_crack)
    xor_crack.add_argument(
        "--max-key-length",
        type=positive_int,
        default=32,
        metavar="N",
        help="largest repeating key length to test (default: 32)",
    )
    xor_crack.add_argument(
        "--key-length",
        type=positive_int,
        metavar="N",
        help="force a repeating-key length",
    )
    xor_crack.add_argument(
        "--raw-input", action="store_true", help="treat TEXT as raw text, not hex"
    )
    mode_group = xor_crack.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--single", action="store_true", help="only try single-byte keys"
    )
    mode_group.add_argument(
        "--repeating", action="store_true", help="only try repeating keys"
    )
    add_output(xor_crack, top_enabled=True, top_default=5, threshold=45.0)

    decode_parser = add_leaf(
        subparsers,
        "decode",
        "Peel layered encodings until readable text remains.",
        """Examples:
  descry decode "NjU2YzZjNmY="
  descry decode "SGVsbG8gV29ybGQ="
  echo "01001000 01101001" | descry decode
""",
        handle_decode,
    )
    add_input(decode_parser)
    decode_parser.add_argument(
        "--max-depth",
        type=positive_int,
        default=6,
        metavar="N",
        help="maximum encoding layers to peel (default: 6)",
    )
    add_output(decode_parser, threshold=25.0)

    freq_parser = add_leaf(
        subparsers,
        "freq",
        "Show letter frequencies, index of coincidence, and chi-squared.",
        """Examples:
  descry freq "The quick brown fox jumps over the lazy dog"
  descry freq -f cipher.txt --format json
""",
        handle_freq,
    )
    add_input(freq_parser)
    add_output(freq_parser)

    return parser


def setup(args: argparse.Namespace) -> tuple[str, str]:
    return output.output_format(args.format), output.color_mode(args.no_color)


def handle_crack(args: argparse.Namespace) -> int:
    text = input_output.read_input(args.text, args.file)
    fmt, mode = setup(args)
    results = rank_results(detect.crack_all(text), args.top)
    output.render_results(results, fmt, mode, title="crack results")
    return 0 if any(result.confidence >= args.threshold for result in results) else 1


def handle_id(args: argparse.Namespace) -> int:
    text = input_output.read_input(args.text, args.file)
    fmt, mode = setup(args)
    results = rank_results(detect.detect(text), args.top)
    output.render_results(
        results,
        fmt,
        mode,
        label_header="TYPE",
        text_header="EVIDENCE",
        title="identification",
    )
    return 0 if any(result.confidence >= args.threshold for result in results) else 1


def handle_caesar_enc(args: argparse.Namespace) -> int:
    text = input_output.read_input(args.text, args.file)
    fmt, mode = setup(args)
    value = caesar.encrypt(text, args.shift)
    output.render_single(
        value,
        fmt,
        mode,
        {"operation": "encrypt", "shift": args.shift, "text": value},
    )
    return 0


def handle_caesar_dec(args: argparse.Namespace) -> int:
    text = input_output.read_input(args.text, args.file)
    fmt, mode = setup(args)
    value = caesar.decrypt(text, args.shift)
    output.render_single(
        value,
        fmt,
        mode,
        {"operation": "decrypt", "shift": args.shift, "text": value},
    )
    return 0


def handle_caesar_brute(args: argparse.Namespace) -> int:
    text = input_output.read_input(args.text, args.file)
    fmt, mode = setup(args)
    results = caesar.brute_force(text, args.top)
    output.render_results(results, fmt, mode, title="caesar brute force")
    return 0 if any(result.confidence >= args.threshold for result in results) else 1


def handle_vigenere_enc(args: argparse.Namespace) -> int:
    text = input_output.read_input(args.text, args.file)
    fmt, mode = setup(args)
    value = vigenere.encrypt(text, args.key)
    output.render_single(
        value,
        fmt,
        mode,
        {"operation": "encrypt", "key": args.key, "text": value},
    )
    return 0


def handle_vigenere_dec(args: argparse.Namespace) -> int:
    text = input_output.read_input(args.text, args.file)
    fmt, mode = setup(args)
    value = vigenere.decrypt(text, args.key)
    output.render_single(
        value,
        fmt,
        mode,
        {"operation": "decrypt", "key": args.key, "text": value},
    )
    return 0


def handle_vigenere_crack(args: argparse.Namespace) -> int:
    text = input_output.read_input(args.text, args.file)
    fmt, mode = setup(args)
    results = vigenere.crack(text, args.max_key_length, args.top)
    output.render_results(results, fmt, mode, title="vigenere crack")
    return 0 if any(result.confidence >= args.threshold for result in results) else 1


def handle_xor_enc(args: argparse.Namespace) -> int:
    text = input_output.read_input(args.text, args.file)
    fmt, mode = setup(args)
    data = xor.bytes_from_input(text, raw=not args.hex_input)
    key = xor.key_from_input(args.key, args.hex_key)
    ciphertext = xor.encrypt(data, key)
    hex_value = ciphertext.hex()
    output.render_single(
        hex_value,
        fmt,
        mode,
        {
            "operation": "encrypt",
            "key": key.hex(),
            "hex": hex_value,
            "text": xor.display_bytes(ciphertext),
        },
    )
    return 0


def handle_xor_dec(args: argparse.Namespace) -> int:
    text = input_output.read_input(args.text, args.file)
    fmt, mode = setup(args)
    data = xor.bytes_from_input(text, raw=args.raw_input)
    key = xor.key_from_input(args.key, args.hex_key)
    plaintext = xor.decrypt(data, key)
    hex_value = plaintext.hex()
    text_value = xor.display_bytes(plaintext)
    value = hex_value if args.hex_output else text_value
    output.render_single(
        value,
        fmt,
        mode,
        {
            "operation": "decrypt",
            "key": key.hex(),
            "hex": hex_value,
            "text": text_value,
        },
    )
    return 0


def handle_xor_crack(args: argparse.Namespace) -> int:
    if args.single and args.key_length is not None:
        raise CliError("--key-length only applies to repeating-key XOR; drop --single")
    text = input_output.read_input(args.text, args.file)
    fmt, mode = setup(args)
    data = xor.bytes_from_input(text, raw=args.raw_input)
    results: list[Result] = []
    if not args.repeating:
        results.extend(xor.single_byte_crack(data, args.top))
    if not args.single:
        results.extend(
            xor.repeating_key_crack(
                data,
                args.max_key_length,
                args.top,
                args.key_length,
            )
        )
    results = dedupe_results(results, args.top, {"0x00"})
    output.render_results(results, fmt, mode, title="xor crack")
    return 0 if any(result.confidence >= args.threshold for result in results) else 1


def handle_decode(args: argparse.Namespace) -> int:
    text = input_output.read_input(args.text, args.file)
    fmt, mode = setup(args)
    final, steps = encodings.peel(text, args.max_depth)
    if fmt == "pretty" and not steps:
        score = confidence(final)
        if score < args.threshold:
            output.write_line(output.paint("no encoding layers found", "muted", mode))
            return 1
    output.render_decode(final, steps, fmt, mode, text)
    return 0 if steps or confidence(final) >= args.threshold else 1


def handle_freq(args: argparse.Namespace) -> int:
    text = input_output.read_input(args.text, args.file)
    fmt, mode = setup(args)
    output.render_frequency(
        frequency_rows(text), frequency_summary(text), fmt, mode
    )
    return 0


def handle_help_request(args: argparse.Namespace) -> int:
    args.group_parser.print_help()
    return 2


def print_error(message: str, no_color: bool = False) -> None:
    mode = output.color_mode(no_color, sys.stderr)
    prefix = output.paint("descry:", "error", mode, bold=True)
    sys.stderr.write(f"{prefix} {message}\n")


def configure_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(errors="replace")
        except (OSError, ValueError):
            pass


def main(argv: Optional[Sequence[str]] = None) -> int:
    configure_streams()
    arguments = list(sys.argv[1:] if argv is None else argv)
    no_color = "--no-color" in arguments
    try:
        parser = build_parser()
        args = parser.parse_args(arguments)
        if getattr(args, "command", None) is None:
            output.render_home(output.color_mode(no_color))
            return 0
        return int(args.handler(args))
    except (CliError, input_output.InputError) as error:
        print_error(str(error), no_color)
        return 2
    except ValueError as error:
        print_error(str(error), no_color)
        return 2
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        return 0
