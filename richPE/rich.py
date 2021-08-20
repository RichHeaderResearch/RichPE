#!/usr/bin/env python3

"""
Implementation of the Rich header md5 hash.
"""

import os
import sys
import pefile
import hashlib
import argparse
from struct import pack

#from https://github.com/dishather/richprint/blob/master/comp_id.txt
#adapted from mirar's implementations for https://www.sweetscape.com/010editor/repository/files/EXE.bt
def get_rich_idVersion(idVersion):
    if idVersion == 0x00010000:
        return "[---] Unmarked objects"
    elif idVersion == 0x00000000:
        return "[---] Unmarked objects (old)"
    elif idVersion == 0x01046b74:
        return "[ C ] VS2019 v16.0.0 build 27508"
    elif idVersion == 0x01036b74:
        return "[ASM] VS2019 v16.0.0 build 27508"
    elif idVersion == 0x01056b74:
        return "[C++] VS2019 v16.0.0 build 27508"
    elif idVersion == 0x00ff6b74:
        return "[RES] VS2019 v16.0.0 build 27508"
    elif idVersion == 0x01026b74:
        return "[LNK] VS2019 v16.0.0 build 27508"
    elif idVersion == 0x01006b74:
        return "[EXP] VS2019 v16.0.0 build 27508"
    elif idVersion == 0x01016b74:
        return "[IMP] VS2019 v16.0.0 build 27508"
    elif idVersion == 0x010464ea:
        return "[ C ] VS2017 v15.5.4 build 25834"
    elif idVersion == 0x010364ea:
        return "[ASM] VS2017 v15.5.4 build 25834"
    elif idVersion == 0x010564ea:
        return "[C++] VS2017 v15.5.4 build 25834"
    elif idVersion == 0x00ff64ea:
        return "[RES] VS2017 v15.5.4 build 25834"
    elif idVersion == 0x010264ea:
        return "[LNK] VS2017 v15.5.4 build 25834"
    elif idVersion == 0x010064ea:
        return "[EXP] VS2017 v15.5.4 build 25834"
    elif idVersion == 0x010164ea:
        return "[IMP] VS2017 v15.5.4 build 25834"
    elif idVersion == 0x01045e97:
        return "[ C ] VS2015 UPD3.1 build 24215"
    elif idVersion == 0x01055e97:
        return "[C++] VS2015 UPD3.1 build 24215"
    elif idVersion == 0x01025e97:
        return "[LNK] VS2015 UPD3.1 build 24215"
    elif idVersion == 0x01005e97:
        return "[EXP] VS2015 UPD3.1 build 24215"
    elif idVersion == 0x01015e97:
        return "[IMP] VS2015 UPD3.1 build 24215"
    elif idVersion == 0x01045e95:
        return "[ C ] VS2015 UPD3 build 24213"
    elif idVersion == 0x01035e92:
        return "[ASM] VS2015 UPD3 build 24210"
    elif idVersion == 0x01055e95:
        return "[C++] VS2015 UPD3 build 24213"
    elif idVersion == 0x00ff5e92:
        return "[RES] VS2015 UPD3 build 24210"
    elif idVersion == 0x01025e95:
        return "[LNK] VS2015 UPD3 build 24213"
    elif idVersion == 0x01005e95:
        return "[EXP] VS2015 UPD3 build 24213"
    elif idVersion == 0x01015e95:
        return "[IMP] VS2015 UPD3 build 24213"
    elif idVersion == 0x01045d6e:
        return "[ C ] VS2015 UPD2 build 23918"
    elif idVersion == 0x01035d6e:
        return "[ASM] VS2015 UPD2 build 23918"
    elif idVersion == 0x01055d6e:
        return "[C++] VS2015 UPD2 build 23918"
    elif idVersion == 0x00ff5d6e:
        return "[RES] VS2015 UPD2 build 23918"
    elif idVersion == 0x01025d6e:
        return "[LNK] VS2015 UPD2 build 23918"
    elif idVersion == 0x01005d6e:
        return "[EXP] VS2015 UPD2 build 23918"
    elif idVersion == 0x01015d6e:
        return "[IMP] VS2015 UPD2 build 23918"
    elif idVersion == 0x01045bd2:
        return "[ C ] VS2015 UPD1 build 23506"
    elif idVersion == 0x01035bd2:
        return "[ASM] VS2015 UPD1 build 23506"
    elif idVersion == 0x01055bd2:
        return "[C++] VS2015 UPD1 build 23506"
    elif idVersion == 0x00ff5bd2:
        return "[RES] VS2015 UPD1 build 23506"
    elif idVersion == 0x01025bd2:
        return "[LNK] VS2015 UPD1 build 23506"
    elif idVersion == 0x01005bd2:
        return "[EXP] VS2015 UPD1 build 23506"
    elif idVersion == 0x01015bd2:
        return "[IMP] VS2015 UPD1 build 23506"
    elif idVersion == 0x010459f2:
        return "[ C ] VS2015 build 23026"
    elif idVersion == 0x010359f2:
        return "[ASM] VS2015 build 23026"
    elif idVersion == 0x010559f2:
        return "[C++] VS2015 build 23026"
    elif idVersion == 0x00ff59f2:
        return "[RES] VS2015 build 23026"
    elif idVersion == 0x010259f2:
        return "[LNK] VS2015 build 23026"
    elif idVersion == 0x010059f2:
        return "[EXP] VS2015 build 23026"
    elif idVersion == 0x010159f2:
        return "[IMP] VS2015 build 23026"
    elif idVersion == 0x00e09eb5:
        return "[ C ] VS2013 UPD5 build 40629"
    elif idVersion == 0x00e19eb5:
        return "[C++] VS2013 UPD5 build 40629"
    elif idVersion == 0x00de9eb5:
        return "[LNK] VS2013 UPD5 build 40629"
    elif idVersion == 0x00dc9eb5:
        return "[EXP] VS2013 UPD5 build 40629"
    elif idVersion == 0x00dd9eb5:
        return "[IMP] VS2013 UPD5 build 40629"
    elif idVersion == 0x00df9eb5:
        return "[ASM] VS2013 UPD5 build 40629"
    elif idVersion == 0x00e0797d:
        return "[ C ] VS2013 UPD4 build 31101"
    elif idVersion == 0x00e1797d:
        return "[C++] VS2013 UPD4 build 31101"
    elif idVersion == 0x00de797d:
        return "[LNK] VS2013 UPD4 build 31101"
    elif idVersion == 0x00dc797d:
        return "[EXP] VS2013 UPD4 build 31101"
    elif idVersion == 0x00dd797d:
        return "[IMP] VS2013 UPD4 build 31101"
    elif idVersion == 0x00df797d:
        return "[ASM] VS2013 UPD4 build 31101"
    elif idVersion == 0x00e07803:
        return "[ C ] VS2013 UPD3 build 30723"
    elif idVersion == 0x00e17803:
        return "[C++] VS2013 UPD3 build 30723"
    elif idVersion == 0x00de7803:
        return "[LNK] VS2013 UPD3 build 30723"
    elif idVersion == 0x00dc7803:
        return "[EXP] VS2013 UPD3 build 30723"
    elif idVersion == 0x00dd7803:
        return "[IMP] VS2013 UPD3 build 30723"
    elif idVersion == 0x00df7803:
        return "[ASM] VS2013 UPD3 build 30723"
    elif idVersion == 0x00e07725:
        return "[ C ] VS2013 UPD2 build 30501"
    elif idVersion == 0x00e17725:
        return "[C++] VS2013 UPD2 build 30501"
    elif idVersion == 0x00de7725:
        return "[LNK] VS2013 UPD2 build 30501"
    elif idVersion == 0x00dc7725:
        return "[EXP] VS2013 UPD2 build 30501"
    elif idVersion == 0x00dd7725:
        return "[IMP] VS2013 UPD2 build 30501"
    elif idVersion == 0x00df7725:
        return "[ASM] VS2013 UPD2 build 30501"
    elif idVersion == 0x00e0520d:
        return "[ C ] VS2013 build 21005"
    elif idVersion == 0x00e1520d:
        return "[C++] VS2013 build 21005"
    elif idVersion == 0x00db520d:
        return "[RES] VS2013 build 21005"
    elif idVersion == 0x00de520d:
        return "[LNK] VS2013 build 21005"
    elif idVersion == 0x00dc520d:
        return "[EXP] VS2013 build 21005"
    elif idVersion == 0x00dd520d:
        return "[IMP] VS2013 build 21005"
    elif idVersion == 0x00df520d:
        return "[ASM] VS2013 build 21005"
    elif idVersion == 0x00ceee66:
        return "[ C ] VS2012 UPD4 build 61030"
    elif idVersion == 0x00cfee66:
        return "[C++] VS2012 UPD4 build 61030"
    elif idVersion == 0x00cdee66:
        return "[ASM] VS2012 UPD4 build 61030"
    elif idVersion == 0x00c9ee66:
        return "[RES] VS2012 UPD4 build 61030"
    elif idVersion == 0x00ccee66:
        return "[LNK] VS2012 UPD4 build 61030"
    elif idVersion == 0x00caee66:
        return "[EXP] VS2012 UPD4 build 61030"
    elif idVersion == 0x00cbee66:
        return "[IMP] VS2012 UPD4 build 61030"
    elif idVersion == 0x00ceecc2:
        return "[ C ] VS2012 UPD3 build 60610"
    elif idVersion == 0x00cfecc2:
        return "[C++] VS2012 UPD3 build 60610"
    elif idVersion == 0x00cdecc2:
        return "[ASM] VS2012 UPD3 build 60610"
    elif idVersion == 0x00c9ecc2:
        return "[RES] VS2012 UPD3 build 60610"
    elif idVersion == 0x00ccecc2:
        return "[LNK] VS2012 UPD3 build 60610"
    elif idVersion == 0x00caecc2:
        return "[EXP] VS2012 UPD3 build 60610"
    elif idVersion == 0x00cbecc2:
        return "[IMP] VS2012 UPD3 build 60610"
    elif idVersion == 0x00ceeb9b:
        return "[ C ] VS2012 UPD2 build 60315"
    elif idVersion == 0x00cfeb9b:
        return "[C++] VS2012 UPD2 build 60315"
    elif idVersion == 0x00cdeb9b:
        return "[ASM] VS2012 UPD2 build 60315"
    elif idVersion == 0x00c9eb9b:
        return "[RES] VS2012 UPD2 build 60315"
    elif idVersion == 0x00cceb9b:
        return "[LNK] VS2012 UPD2 build 60315"
    elif idVersion == 0x00caeb9b:
        return "[EXP] VS2012 UPD2 build 60315"
    elif idVersion == 0x00cbeb9b:
        return "[IMP] VS2012 UPD2 build 60315"
    elif idVersion == 0x00cec7a2:
        return "[ C ] VS2012 UPD1 build 51106"
    elif idVersion == 0x00cfc7a2:
        return "[C++] VS2012 UPD1 build 51106"
    elif idVersion == 0x00cdc7a2:
        return "[ASM] VS2012 UPD1 build 51106"
    elif idVersion == 0x00c9c7a2:
        return "[RES] VS2012 UPD1 build 51106"
    elif idVersion == 0x00ccc7a2:
        return "[LNK] VS2012 UPD1 build 51106"
    elif idVersion == 0x00cac7a2:
        return "[EXP] VS2012 UPD1 build 51106"
    elif idVersion == 0x00cbc7a2:
        return "[IMP] VS2012 UPD1 build 51106"
    elif idVersion == 0x00cec627:
        return "[ C ] VS2012 build 50727"
    elif idVersion == 0x00cfc627:
        return "[C++] VS2012 build 50727"
    elif idVersion == 0x00c9c627:
        return "[RES] VS2012 build 50727"
    elif idVersion == 0x00cdc627:
        return "[ASM] VS2012 build 50727"
    elif idVersion == 0x00cac627:
        return "[EXP] VS2012 build 50727"
    elif idVersion == 0x00cbc627:
        return "[IMP] VS2012 build 50727"
    elif idVersion == 0x00ccc627:
        return "[LNK] VS2012 build 50727"
    elif idVersion == 0x00aa9d1b:
        return "[ C ] VS2010 SP1 build 40219"
    elif idVersion == 0x00ab9d1b:
        return "[C++] VS2010 SP1 build 40219"
    elif idVersion == 0x009d9d1b:
        return "[LNK] VS2010 SP1 build 40219"
    elif idVersion == 0x009a9d1b:
        return "[RES] VS2010 SP1 build 40219"
    elif idVersion == 0x009b9d1b:
        return "[EXP] VS2010 SP1 build 40219"
    elif idVersion == 0x009c9d1b:
        return "[IMP] VS2010 SP1 build 40219"
    elif idVersion == 0x009e9d1b:
        return "[ASM] VS2010 SP1 build 40219"
    elif idVersion == 0x00aa766f:
        return "[ C ] VS2010 build 30319"
    elif idVersion == 0x00ab766f:
        return "[C++] VS2010 build 30319"
    elif idVersion == 0x009d766f:
        return "[LNK] VS2010 build 30319"
    elif idVersion == 0x009a766f:
        return "[RES] VS2010 build 30319"
    elif idVersion == 0x009b766f:
        return "[EXP] VS2010 build 30319"
    elif idVersion == 0x009c766f:
        return "[IMP] VS2010 build 30319"
    elif idVersion == 0x009e766f:
        return "[ASM] VS2010 build 30319"
    elif idVersion == 0x00837809:
        return "[ C ] VS2008 SP1 build 30729"
    elif idVersion == 0x00847809:
        return "[C++] VS2008 SP1 build 30729"
    elif idVersion == 0x00957809:
        return "[ASM] VS2008 SP1 build 30729"
    elif idVersion == 0x00927809:
        return "[EXP] VS2008 SP1 build 30729"
    elif idVersion == 0x00937809:
        return "[IMP] VS2008 SP1 build 30729"
    elif idVersion == 0x00917809:
        return "[LNK] VS2008 SP1 build 30729"
    elif idVersion == 0x0083521e:
        return "[ C ] VS2008 build 21022"
    elif idVersion == 0x0084521e:
        return "[C++] VS2008 build 21022"
    elif idVersion == 0x0091521e:
        return "[LNK] VS2008 build 21022"
    elif idVersion == 0x0094521e:
        return "[RES] VS2008 build 21022"
    elif idVersion == 0x0092521e:
        return "[EXP] VS2008 build 21022"
    elif idVersion == 0x0093521e:
        return "[IMP] VS2008 build 21022"
    elif idVersion == 0x0095521e:
        return "[ASM] VS2008 build 21022"
    elif idVersion == 0x006dc627:
        return "[ C ] VS2005 build 50727"
    elif idVersion == 0x006ec627:
        return "[C++] VS2005 build 50727"
    elif idVersion == 0x0078c627:
        return "[LNK] VS2005 build 50727"
    elif idVersion == 0x007cc627:
        return "[RES] VS2005 build 50727"
    elif idVersion == 0x007ac627:
        return "[EXP] VS2005 build 50727"
    elif idVersion == 0x007bc627:
        return "[IMP] VS2005 build 50727"
    elif idVersion == 0x007dc627:
        return "[ASM] VS2005 build 50727"
    elif idVersion == 0x005f178e:
        return "[ C ] VS2003 (.NET) SP1 build 6030"
    elif idVersion == 0x0060178e:
        return "[C++] VS2003 (.NET) SP1 build 6030"
    elif idVersion == 0x005a178e:
        return "[LNK] VS2003 (.NET) SP1 build 6030"
    elif idVersion == 0x000f178e:
        return "[ASM] VS2003 (.NET) SP1 build 6030"
    elif idVersion == 0x005c178e:
        return "[EXP] VS2003 (.NET) SP1 build 6030"
    elif idVersion == 0x005d178e:
        return "[IMP] VS2003 (.NET) SP1 build 6030"
    elif idVersion == 0x005f0c05:
        return "[ C ] VS2003 (.NET) build 3077"
    elif idVersion == 0x00600c05:
        return "[C++] VS2003 (.NET) build 3077"
    elif idVersion == 0x000f0c05:
        return "[ASM] VS2003 (.NET) build 3077"
    elif idVersion == 0x005e0bec:
        return "[RES] VS2003 (.NET) build 3052"
    elif idVersion == 0x005c0c05:
        return "[EXP] VS2003 (.NET) build 3077"
    elif idVersion == 0x005d0c05:
        return "[IMP] VS2003 (.NET) build 3077"
    elif idVersion == 0x005a0c05:
        return "[LNK] VS2003 (.NET) build 3077"
    elif idVersion == 0x001c24fa:
        return "[ C ] VS2002 (.NET) build 9466"
    elif idVersion == 0x001d24fa:
        return "[C++] VS2002 (.NET) build 9466"
    elif idVersion == 0x004024fa:
        return "[ASM] VS2002 (.NET) build 9466"
    elif idVersion == 0x003d24fa:
        return "[LNK] VS2002 (.NET) build 9466"
    elif idVersion == 0x004524fa:
        return "[RES] VS2002 (.NET) build 9466"
    elif idVersion == 0x003f24fa:
        return "[EXP] VS2002 (.NET) build 9466"
    elif idVersion == 0x001924fa:
        return "[IMP] VS2002 (.NET) build 9466"
    elif idVersion == 0x000a2636:
        return "[ C ] VS98 (6.0) SP6 build 8804"
    elif idVersion == 0x000b2636:
        return "[C++] VS98 (6.0) SP6 build 8804"
    elif idVersion == 0x00152306:
        return "[ C ] VC++ 6.0 SP5 build 8804"
    elif idVersion == 0x00162306:
        return "[C++] VC++ 6.0 SP5 build 8804"
    elif idVersion == 0x000420ff:
        return "[LNK] VC++ 6.0 SP5 imp/exp build 8447"
    elif idVersion == 0x000606c7:
        return "[RES] VS98 (6.0) SP6 cvtres build 1736"
    elif idVersion == 0x000a1fe8:
        return "[ C ] VS98 (6.0) build 8168"
    elif idVersion == 0x000b1fe8:
        return "[C++] VS98 (6.0) build 8168"
    elif idVersion == 0x000606b8:
        return "[RES] VS98 (6.0) cvtres build 1720"
    elif idVersion == 0x00041fe8:
        return "[LNK] VS98 (6.0) imp/exp build 8168"
    elif idVersion == 0x00060684:
        return "[RES] VS97 (5.0) SP3 cvtres 5.00.1668"
    elif idVersion == 0x00021c87:
        return "[IMP] VS97 (5.0) SP3 link 5.10.7303"
    else:
        id = idVersion >> 0x10
        version = idVersion & 0xffff
        s = "id: " + str(id) + ", version: " + str(version)
        return s

def get_rich_info(file_path=None, data=None):
    """Computes the Rich header info given a file path or data.

    If the Rich header hash is unable to be computed, returns None.
    Otherwise, returns the computed Rich header information.

    If both file_path and data are provided, file_path is used by default.
    """

    # Must provide either file path or data
    if file_path is None and data is None:
        raise ValueError("Must provide a file path or data")

    # Attempt to parse PE header
    try:
        pe = pefile.PE(name=file_path, data=data, fast_load=True)
    except pefile.PEFormatError:
        return None

    # Attempt to parse Rich header
    rich_header = pe.parse_rich_header()
    if rich_header is None:
        return None

    # Get list of @Comp.IDs and counts from Rich header
    # Elements in rich_fields at even indices are @Comp.IDs
    # Elements in rich_fields at odd indices are counts
    rich_fields = rich_header.get("values", None)
    if len(rich_fields) % 2 != 0:
        return None

    richinfos = []
    compid = None
    for i in rich_fields:
        if rich_fields.index(i) % 2 == 0:
            #even -> save value
            compid = get_rich_idVersion(i)
        else:
            #odd -> add to list
            if compid:
                richinfos.append(compid + " count=%d" % i)
                compid = None

    # Close PE file and return Rich Header information
    pe.close()
    return '\n'.join(richinfos)

def get_rich_hash(file_path=None, data=None):
    """Computes the Rich header hash given a file path or data.

    If the Rich header hash is unable to be computed, returns None.
    Otherwise, returns the computed Rich header hash.

    If both file_path and data are provided, file_path is used by default.
    """

    # Must provide either file path or data
    if file_path is None and data is None:
        raise ValueError("Must provide a file path or data")

    # Attempt to parse PE header
    try:
        pe = pefile.PE(name=file_path, data=data, fast_load=True)
    except pefile.PEFormatError:
        return None

    # Attempt to parse Rich header
    rich_header = pe.parse_rich_header()
    if rich_header is None:
        return None

    # Get list of @Comp.IDs and counts from Rich header
    # Elements in rich_fields at even indices are @Comp.IDs
    # Elements in rich_fields at odd indices are counts
    rich_fields = rich_header.get("values", None)
    if len(rich_fields) % 2 != 0:
        return None

    # The Rich header hash of a file is computed by computing the md5 of the
    # decoded rich header without the rich magic and the xor key, but with
    # the dans magic. It can be used with yara hash.md5(pe.rich_signature.clear_data)
    md5 = hashlib.md5()
    md5.update(rich_header["clear_data"])
    
    # Close PE file and return Rich Header md5 hash
    pe.close()
    return md5.hexdigest()

if __name__ == "__main__":

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Rich header hash implementation")
    parser.add_argument("file_paths", type=str, nargs="+",
                        help="A list of file paths")
    args = parser.parse_args()

    # Compute and print Rich header hash of each file
    for file_path in args.file_paths:
        if not os.path.isfile(file_path):
            raise ValueError("Invalid file path: {}".format(file_path))

        rich_hash = get_rich_hash(file_path)
        rich_info = get_rich_info(file_path)
        file_name = os.path.basename(file_path)
        print("{}\t{}".format(file_name, rich_hash))
        print(rich_info)
