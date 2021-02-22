import os
import sys
import copy
import pefile
import struct
import argparse
from enum import Enum

"""
Checks that the metadata within a file's Rich header does not contradict the
other metadata contained within it.

References:
    https://gist.github.com/skochinsky/07c8e95e33d9429d81a75622b5d24c8b
    https://www.sec.in.tum.de/i20/publications/finding-the-needle-a-study-of-
    the-pe32-rich-header-and-respective-malware-triage
"""

KNOWN_PRODUCT_IDS = {
  0: "Unknown",
  1: "Import0",
  2: "Linker510",
  3: "Cvtomf510",
  4: "Linker600",
  5: "Cvtomf600",
  6: "Cvtres500",
  7: "Utc11_Basic",
  8: "Utc11_C",
  9: "Utc12_Basic",
  10: "Utc12_C",
  11: "Utc12_CPP",
  12: "AliasObj60",
  13: "VisualBasic60",
  14: "Masm613",
  15: "Masm710",
  16: "Linker511",
  17: "Cvtomf511",
  18: "Masm614",
  19: "Linker512",
  20: "Cvtomf512",
  21: "Utc12_C_Std",
  22: "Utc12_CPP_Std",
  23: "Utc12_C_Book",
  24: "Utc12_CPP_Book",
  25: "Implib700",
  26: "Cvtomf700",
  27: "Utc13_Basic",
  28: "Utc13_C",
  29: "Utc13_CPP",
  30: "Linker610",
  31: "Cvtomf610",
  32: "Linker601",
  33: "Cvtomf601",
  34: "Utc12_1_Basic",
  35: "Utc12_1_C",
  36: "Utc12_1_CPP",
  37: "Linker620",
  38: "Cvtomf620",
  39: "AliasObj70",
  40: "Linker621",
  41: "Cvtomf621",
  42: "Masm615",
  43: "Utc13_LTCG_C",
  44: "Utc13_LTCG_CPP",
  45: "Masm620",
  46: "ILAsm100",
  47: "Utc12_2_Basic",
  48: "Utc12_2_C",
  49: "Utc12_2_CPP",
  50: "Utc12_2_C_Std",
  51: "Utc12_2_CPP_Std",
  52: "Utc12_2_C_Book",
  53: "Utc12_2_CPP_Book",
  54: "Implib622",
  55: "Cvtomf622",
  56: "Cvtres501",
  57: "Utc13_C_Std",
  58: "Utc13_CPP_Std",
  59: "Cvtpgd1300",
  60: "Linker622",
  61: "Linker700",
  62: "Export622",
  63: "Export700",
  64: "Masm700",
  65: "Utc13_POGO_I_C",
  66: "Utc13_POGO_I_CPP",
  67: "Utc13_POGO_O_C",
  68: "Utc13_POGO_O_CPP",
  69: "Cvtres700",
  70: "Cvtres710p",
  71: "Linker710p",
  72: "Cvtomf710p",
  73: "Export710p",
  74: "Implib710p",
  75: "Masm710p",
  76: "Utc1310p_C",
  77: "Utc1310p_CPP",
  78: "Utc1310p_C_Std",
  79: "Utc1310p_CPP_Std",
  80: "Utc1310p_LTCG_C",
  81: "Utc1310p_LTCG_CPP",
  82: "Utc1310p_POGO_I_C",
  83: "Utc1310p_POGO_I_CPP",
  84: "Utc1310p_POGO_O_C",
  85: "Utc1310p_POGO_O_CPP",
  86: "Linker624",
  87: "Cvtomf624",
  88: "Export624",
  89: "Implib624",
  90: "Linker710",
  91: "Cvtomf710",
  92: "Export710",
  93: "Implib710",
  94: "Cvtres710",
  95: "Utc1310_C",
  96: "Utc1310_CPP",
  97: "Utc1310_C_Std",
  98: "Utc1310_CPP_Std",
  99: "Utc1310_LTCG_C",
  100: "Utc1310_LTCG_CPP",
  101: "Utc1310_POGO_I_C",
  102: "Utc1310_POGO_I_CPP",
  103: "Utc1310_POGO_O_C",
  104: "Utc1310_POGO_O_CPP",
  105: "AliasObj710",
  106: "AliasObj710p",
  107: "Cvtpgd1310",
  108: "Cvtpgd1310p",
  109: "Utc1400_C",
  110: "Utc1400_CPP",
  111: "Utc1400_C_Std",
  112: "Utc1400_CPP_Std",
  113: "Utc1400_LTCG_C",
  114: "Utc1400_LTCG_CPP",
  115: "Utc1400_POGO_I_C",
  116: "Utc1400_POGO_I_CPP",
  117: "Utc1400_POGO_O_C",
  118: "Utc1400_POGO_O_CPP",
  119: "Cvtpgd1400",
  120: "Linker800",
  121: "Cvtomf800",
  122: "Export800",
  123: "Implib800",
  124: "Cvtres800",
  125: "Masm800",
  126: "AliasObj800",
  127: "PhoenixPrerelease",
  128: "Utc1400_CVTCIL_C",
  129: "Utc1400_CVTCIL_CPP",
  130: "Utc1400_LTCG_MSIL",
  131: "Utc1500_C",
  132: "Utc1500_CPP",
  133: "Utc1500_C_Std",
  134: "Utc1500_CPP_Std",
  135: "Utc1500_CVTCIL_C",
  136: "Utc1500_CVTCIL_CPP",
  137: "Utc1500_LTCG_C",
  138: "Utc1500_LTCG_CPP",
  139: "Utc1500_LTCG_MSIL",
  140: "Utc1500_POGO_I_C",
  141: "Utc1500_POGO_I_CPP",
  142: "Utc1500_POGO_O_C",
  143: "Utc1500_POGO_O_CPP",

  144: "Cvtpgd1500",
  145: "Linker900",
  146: "Export900",
  147: "Implib900",
  148: "Cvtres900",
  149: "Masm900",
  150: "AliasObj900",
  151: "Resource900",

  152: "AliasObj1000",
  154: "Cvtres1000",
  155: "Export1000",
  156: "Implib1000",
  157: "Linker1000",
  158: "Masm1000",

  170: "Utc1600_C",
  171: "Utc1600_CPP",
  172: "Utc1600_CVTCIL_C",
  173: "Utc1600_CVTCIL_CPP",
  174: "Utc1600_LTCG_C ",
  175: "Utc1600_LTCG_CPP",
  176: "Utc1600_LTCG_MSIL",
  177: "Utc1600_POGO_I_C",
  178: "Utc1600_POGO_I_CPP",
  179: "Utc1600_POGO_O_C",
  180: "Utc1600_POGO_O_CPP",

  183: "Linker1010",
  184: "Export1010",
  185: "Implib1010",
  186: "Cvtres1010",
  187: "Masm1010",
  188: "AliasObj1010",

  199: "AliasObj1100",
  201: "Cvtres1100",
  202: "Export1100",
  203: "Implib1100",
  204: "Linker1100",
  205: "Masm1100",

  206: "Utc1700_C",
  207: "Utc1700_CPP",
  208: "Utc1700_CVTCIL_C",
  209: "Utc1700_CVTCIL_CPP",
  210: "Utc1700_LTCG_C ",
  211: "Utc1700_LTCG_CPP",
  212: "Utc1700_LTCG_MSIL",
  213: "Utc1700_POGO_I_C",
  214: "Utc1700_POGO_I_CPP",
  215: "Utc1700_POGO_O_C",
  216: "Utc1700_POGO_O_CPP",

  219: "Cvtres1200",
  220: "Export1200",
  221: "Implib1200",
  222: "Linker1200",
  223: "Masm1200",
  # Speculation
  224: "AliasObj1200",

  237: "Cvtres1210",
  238: "Export1210",
  239: "Implib1210",
  240: "Linker1210",
  241: "Masm1210",
  # Speculation
  242: "Utc1810_C",
  243: "Utc1810_CPP",
  244: "Utc1810_CVTCIL_C",
  245: "Utc1810_CVTCIL_CPP",
  246: "Utc1810_LTCG_C ",
  247: "Utc1810_LTCG_CPP",
  248: "Utc1810_LTCG_MSIL",
  249: "Utc1810_POGO_I_C",
  250: "Utc1810_POGO_I_CPP",
  251: "Utc1810_POGO_O_C",
  252: "Utc1810_POGO_O_CPP",

  255: "Cvtres1400",
  256: "Export1400",
  257: "Implib1400",
  258: "Linker1400",
  259: "Masm1400",

  260: "Utc1900_C",
  261: "Utc1900_CPP",
  # Speculation
  262: "Utc1900_CVTCIL_C",
  263: "Utc1900_CVTCIL_CPP",
  264: "Utc1900_LTCG_C ",
  265: "Utc1900_LTCG_CPP",
  266: "Utc1900_LTCG_MSIL",
  267: "Utc1900_POGO_I_C",
  268: "Utc1900_POGO_I_CPP",
  269: "Utc1900_POGO_O_C",
  270: "Utc1900_POGO_O_CPP"
}


class result(Enum):
    VALID = 0
    INVALID = 1
    UNABLE_TO_PARSE = 2


def _rol(val, num):
    """Rotates val to the left by num bits."""
    return ((val << (num % 32)) & 0xffffffff) | (val >> (32 - (num % 32)))


def checksum_test(pe, rich_header):
    """Tests that the Rich header checksum is valid.

    Computes what the Rich header checksum should be. If the Rich header
    contains a different checksum value, this function returns INVALID
    This indicates that either the Rich header or MS-DOS stub has been modified

    The Rich header checksum is computed from the following:
        Length of the MS-DOS stub
        Contents of the MS-DOS stub, with e_lfanew zeroed out
        Rich header @Comp.IDs and lowest 5 bits of each count
    """

    # Checksum stored in Rich header
    rich_checksum = rich_header.get("checksum", None)

    # Get DOS header data
    if pe.DOS_HEADER.e_lfanew > len(pe.__data__):
        return result.UNABLE_TO_PARSE
    data = pe.__data__[:pe.DOS_HEADER.e_lfanew]

    # Get start marker
    mask = 0x536e6144 # DanS (little-endian)
    start_marker = struct.pack("<LLLL", rich_checksum ^ mask, rich_checksum,
                               rich_checksum, rich_checksum)
    if not len(start_marker):
        return result.UNABLE_TO_PARSE

    # Get index of start marker
    start_index = data.find(start_marker)
    if start_index == -1:
        return result.UNABLE_TO_PARSE

    # Get list of @Comp.IDs and counts from Rich header
    # Elements in rich_fields at even indices are @Comp.IDs
    # Elements in rich_fields at odd indices are counts
    rich_fields = copy.deepcopy(rich_header.get("values", None))
    if len(rich_fields) % 2 != 0:
        return result.UNABLE_TO_PARSE

    # Compute cd as MS-DOS stub portion of checksum
    # Zero out e_lfanew from 0x3c to 0x3f
    cd = 0
    for i in range(start_index):
        if i >= 0x3c and i <= 0x3f:
            cd += _rol(0, i)
        else:
            cd += _rol(data[i], i)

    # Compute cd as Rich header portion of checksum
    cr = 0
    while len(rich_fields):
        compid = rich_fields.pop(0)
        count = rich_fields.pop(0)
        cr += _rol(compid, count & 0x1f)

    # Compute checksum from MS-DOS stub start index, cd, cr
    # Only keep lowest 32 bits
    checksum = (start_index + cd + cr) & 0xffffffff

    # Compare computed checksum with the checksum in the Rich header
    if checksum != rich_checksum:
        return result.INVALID
    else:
        return result.VALID


def duplicate_test(pe, rich_header):
    """Checks for duplicate @Comp.IDs in the Rich header.

    If the Rich header contains duplicate entries, returns INVALID
    This indicates that the Rich header has been modified
    """

    # Get list of @Comp.IDs and counts from Rich header
    # Elements in rich_fields at even indices are @Comp.IDs
    # Elements in rich_fields at odd indices are counts
    rich_fields = copy.deepcopy(rich_header.get("values", None))
    if len(rich_fields) % 2 != 0:
        return result.UNABLE_TO_PARSE

    # Get a list of @Comp.IDs in rich_fields
    compids = []
    for i in range(len(rich_fields)):
        if i % 2 == 0:
            compids.append(rich_fields[i])

    # Check if any @Comp.IDs are duplicates
    if len(compids) != len(set(compids)):
        return result.INVALID

    return result.VALID


def linker_test(pe, rich_header):
    """Checks that the Rich and PE header linker versions do not conflict.

    Certain Rich Header ProdIDs correspond to linker versions
    Although they are undocumented, we have used prior research as well as our
    own to determine many of them
    There are likely more linker version ProdIDs that we have not identified

    If the linker versions conflict, this function returns INVALID
    This indicates that the Rich header or PE header has been modified
    """

    # Get list of @Comp.IDs and counts from Rich header
    # Elements in rich_fields at even indices are @Comp.IDs
    # Elements in rich_fields at odd indices are counts
    rich_fields = copy.deepcopy(rich_header.get("values", None))
    if len(rich_fields) % 2 != 0:
        return result.UNABLE_TO_PARSE

    # Get list of ProdIDs from rich_fields
    prodids = []
    for i in range(len(rich_fields)):
        if i % 2 == 0:
            prodids.append(rich_fields[i] >> 16)

    # Parse major and minor linker versions from PE header
    pe_major = pe.OPTIONAL_HEADER.MajorLinkerVersion
    pe_minor = pe.OPTIONAL_HEADER.MinorLinkerVersion

    # Iterate over Rich header ProdIDs
    found_linker = False
    for prodid in prodids:

        # Only interested in ProdIDs that correspond to linker versions
        if KNOWN_PRODUCT_IDS.get(prodid) is None:
            continue
        prodid_name = KNOWN_PRODUCT_IDS[prodid]
        if not prodid_name.startswith("Linker"):
            continue

        found_linker = True

        # Parse major and minor linker version from ProdID
        prodid_name = prodid_name[6:]
        if prodid_name.endswith("p"):
            prodid_name = prodid_name[:-1]
        rich_major = int(prodid_name[:-2])
        rich_minor = int(prodid_name[-2:])

        # Check whether the Rich and PE linker versions match
        if pe_major == rich_major and pe_minor == rich_minor:
            return result.VALID

    if not found_linker:
        return result.UNABLE_TO_PARSE

    return result.INVALID


def import_count_test(pe, rich_header):
    """Checks that import0 does not conflict with the IAT import count.

    The Rich header contains a ProdID called import0
    It is related to the number of imports in the IAT, but we are unsure how
    It is never less than the number of imports in the IAT

    If import0 is less than IAT import count, this function returns INVALID
    This indicates that the Rich header or IAT has been modified
    """

    # Check whether the file has an IAT
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return result.UNABLE_TO_PARSE

    # Get the number of imports in the IAT
    iat_count = 0
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imported_function in entry.imports:
            iat_count += 1

    # Get list of @Comp.IDs and counts from Rich header
    # Elements in rich_fields at even indices are @Comp.IDs
    # Elements in rich_fields at odd indices are counts
    rich_fields = copy.deepcopy(rich_header.get("values", None))
    if len(rich_fields) % 2 != 0:
        return result.INVALID

    # Get @Comp.ID 65536 (ProdID Import0)
    import0_count = None
    while len(rich_fields):
        compid = rich_fields.pop(0)
        count = rich_fields.pop(0)
        if compid == 65536:
            import0_count = count

    # Legitimate files never have import0_count < iat_count
    if import0_count is None:
        return result.VALID

    if import0_count < iat_count:
        return result.INVALID

    return result.VALID


if __name__ == "__main__":

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="PE meta tampering checker")
    parser.add_argument("-v", "--verbose", action="store_true", default=False,
                        help="Run in verbose mode")
    parser.add_argument("file_paths", type=str, nargs="+",
                        help="A list of file paths")
    args = parser.parse_args()

    # List of tests to identify invalid metadata
    meta_tests = [
        checksum_test,
        duplicate_test,
        linker_test,
        import_count_test
    ]

    # Perform tests on each file
    for file_path in args.file_paths:
        if not os.path.isfile(file_path):
            raise ValueError("Invalid file path: {}".format(file_path))
        file_name = os.path.basename(file_path)

        # Attempt to parse PE header
        try:
            pe = pefile.PE(name=file_path)
        except pefile.PEFormatError:
            if args.verbose:
                print("{}\n\tUnable to parse: PE header".format(file_name))
            continue

        # Attempt to parse Rich header:
        rich_header = pe.parse_rich_header()
        if rich_header is None:
            if args.verbose:
                print("{}\n\tUnable to parse: Rich header".format(file_name))
            continue

        # Perform tests
        test_results = []
        failed_test = False
        for meta_test in meta_tests:
            test_name = meta_test.__name__
            res = meta_test(pe, rich_header)
            pe.close()

            if res == result.INVALID:
                test_results.append("\tFailed: {}".format(test_name))
                failed_test = True
            elif res == result.UNABLE_TO_PARSE:
                test_results.append("\tUnable to parse: {}".format(test_name))

        # Print test results
        if failed_test or args.verbose:
            print(file_name)
            for test_result in test_results:
                if test_result.startswith("\tFailed:"):
                    print(test_result)
                elif args.verbose:
                    print(test_result)
