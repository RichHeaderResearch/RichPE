import os
import sys
import pefile
import hashlib


"""
Usage: python3 richpe.py [file_path]
"""


def get_richpe(file_path):

    # Check if file_path is a valid PE file
    try:
        pe = pefile.PE(name=file_path, fast_load=True)
    except Exception:
        return None

    # Check if file has a valid Rich header
    rich_header = pe.parse_rich_header()
    if rich_header is None:
        return None
    rich_fields = rich_header.get("values", None)
    if len(rich_fields) % 2 != 0:
        return None

    # Make a list of Rich header and PE header features
    features = []
    while len(rich_fields):
        compid = rich_fields.pop(0)
        count = rich_fields.pop(0)
        mask = 2 ** (count.bit_length() // 2 + 1) - 1
        count |= mask
        features.append(str(compid))
        features.append(str(count))

    features.append(str(pe.FILE_HEADER.Machine))
    features.append(str(pe.FILE_HEADER.Characteristics))
    features.append(str(pe.OPTIONAL_HEADER.Subsystem))
    features.append(str(pe.OPTIONAL_HEADER.MajorLinkerVersion))
    features.append(str(pe.OPTIONAL_HEADER.MinorLinkerVersion))
    features.append(str(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion))
    features.append(str(pe.OPTIONAL_HEADER.MinorOperatingSystemVersion))
    features.append(str(pe.OPTIONAL_HEADER.MajorImageVersion))
    features.append(str(pe.OPTIONAL_HEADER.MinorImageVersion))
    features.append(str(pe.OPTIONAL_HEADER.MajorSubsystemVersion))
    features.append(str(pe.OPTIONAL_HEADER.MinorSubsystemVersion))

    # Close PE file
    pe.close()

    # Generate RichPE hash from features
    md5 = hashlib.md5()
    md5.update(" ".join(features).encode("ascii"))
    return md5.hexdigest()


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("[E] Invalid arguments")
        sys.exit(1)

    file_path = sys.argv[1]
    if not os.path.isfile(file_path):
        print("[E] Invalid file path: {}".format(file_path))
        sys.exit(1)

    richpe = get_richpe(file_path)
    file_name = os.path.basename(file_path)
    print("{}\t{}".format(file_name, richpe))
