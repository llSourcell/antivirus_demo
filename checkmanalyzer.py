#!/usr/bin/env python2
import argparse
import pickle
import requests
import sys
import os
from sklearn.externals import joblib

MACHINE_TYPES = {
    "IMAGE_FILE_MACHINE_UNKNOWN": 0,
    "IMAGE_FILE_MACHINE_I386": 0x014c,
    "IMAGE_FILE_MACHINE_R3000":	0x0162,
    "IMAGE_FILE_MACHINE_R4000": 0x0166,
    "IMAGE_FILE_MACHINE_R10000": 0x0168,
    "IMAGE_FILE_MACHINE_WCEMIPSV2": 0x0169,
    "IMAGE_FILE_MACHINE_ALPHA": 0x0184,
    "IMAGE_FILE_MACHINE_SH3": 0x01a2,
    "IMAGE_FILE_MACHINE_SH3DSP": 0x01a3,
    "IMAGE_FILE_MACHINE_SH3E": 0x01a4,
    "IMAGE_FILE_MACHINE_SH4": 0x01a6,
    "IMAGE_FILE_MACHINE_SH5": 0x01a8,
    "IMAGE_FILE_MACHINE_ARM": 0x01c0,
    "IMAGE_FILE_MACHINE_THUMB": 0x01c2,
    "IMAGE_FILE_MACHINE_AM33": 0x01d3,
    "IMAGE_FILE_MACHINE_POWERPC": 0x01F0,
    "IMAGE_FILE_MACHINE_POWERPCFP": 0x01f1,
    "IMAGE_FILE_MACHINE_IA64": 0x0200,
    "IMAGE_FILE_MACHINE_MIPS16": 0x0266,
    "IMAGE_FILE_MACHINE_ALPHA64": 0x0284,
    "IMAGE_FILE_MACHINE_MIPSFPU": 0x0366,
    "IMAGE_FILE_MACHINE_MIPSFPU16": 0x0466,
    "IMAGE_FILE_MACHINE_TRICORE": 0x0520,
    "IMAGE_FILE_MACHINE_CEF": 0x0CEF,
    "IMAGE_FILE_MACHINE_EBC": 0x0EBC,
    "IMAGE_FILE_MACHINE_AMD64": 0x8664,
    "IMAGE_FILE_MACHINE_M32R": 	0x9041,
    "IMAGE_FILE_MACHINE_CEE": 0xC0EE
}

PE_CHARACTERISTICS = {
    "IMAGE_FILE_RELOCS_STRIPPED": 0x0001,
    "IMAGE_FILE_EXECUTABLE_IMAGE": 0x0002,
    "IMAGE_FILE_LINE_NUMS_STRIPPED": 0x0004,
    "IMAGE_FILE_LOCAL_SYMS_STRIPPED": 0x0008,
    "IMAGE_FILE_AGGRESIVE_WS_TRIM": 0x0010,
    "IMAGE_FILE_LARGE_ADDRESS_AWARE": 0x0020,
    "IMAGE_FILE_BYTES_REVERSED_LO": 0x0080,
    "IMAGE_FILE_32BIT_MACHINE": 0x0100,
    "IMAGE_FILE_DEBUG_STRIPPED": 0x0200,
    "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP": 0x0400,
    "IMAGE_FILE_NET_RUN_FROM_SWAP": 0x0800,
    "IMAGE_FILE_SYSTEM": 0x1000,
    "IMAGE_FILE_DLL": 0x2000,
    "IMAGE_FILE_UP_SYSTEM_ONLY": 0x4000,
    "IMAGE_FILE_BYTES_REVERSED_HI": 0x8000
}

SUBSYSTEMS = {
    "IMAGE_SUBSYSTEM_UNKNOWN": 0,
    "IMAGE_SUBSYSTEM_NATIVE": 1,
    "IMAGE_SUBSYSTEM_WINDOWS_GUI": 2,
    "IMAGE_SUBSYSTEM_WINDOWS_CUI": 3,
    "IMAGE_SUBSYSTEM_POSIX_CUI": 7,
    "IMAGE_SUBSYSTEM_NATIVE_WINDOWS": 8,
    "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI": 9,
    "IMAGE_SUBSYSTEM_EFI_APPLICATION": 10,
    "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER": 11,
    "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER": 12,
    "IMAGE_SUBSYSTEM_EFI_ROM": 13,
    "IMAGE_SUBSYSTEM_XBOX": 14,
    "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION": 16,
}

DLL_CHARACTERISTICS = {
	"IMAGE_LIBRARY_PROCESS_INIT": 0x0001,
	"IMAGE_LIBRARY_PROCESS_TERM": 0x0002,
	"IMAGE_LIBRARY_THREAD_INIT": 0x0004,
	"IMAGE_LIBRARY_THREAD_TERM": 0x0008,
	"IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA": 0x0020,
	"IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE": 0x0040,
	"IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY": 0x0080,
	"IMAGE_DLLCHARACTERISTICS_NX_COMPAT": 0x0100,
	"IMAGE_DLLCHARACTERISTICS_NO_ISOLATION": 0x0200,
	"IMAGE_DLLCHARACTERISTICS_NO_SEH": 0x0400,
	"IMAGE_DLLCHARACTERISTICS_NO_BIND": 0x0800,
	"IMAGE_DLLCHARACTERISTICS_APPCONTAINER": 0x1000,
	"IMAGE_DLLCHARACTERISTICS_WDM_DRIVER": 0x2000,
	"IMAGE_DLLCHARACTERISTICS_GUARD_CF": 0x4000,
	"IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE": 0x8000
}


def get_data(url):
    """Download json data from manamyzer url"""
    r = requests.get(url)
    return r.json()

def feature_extraction(data):
    """Extract the features from manalyzer data"""
    features = {}
    md5 = data.keys()[0]
    data = data[md5]
    features['md5'] = md5
    features['Machine']= MACHINE_TYPES[data['PE Header']['Machine']]
    features['SizeOfOptionalHeader'] = data['PE Header']['SizeOfOptionalHeader']
    features['Characteristics'] = 0
    for charac in data['PE Header']['Characteristics']:
        features['Characteristics'] += PE_CHARACTERISTICS[charac]
    features['SizeOfCode'] = data['Image Optional Header']['SizeOfCode']
    features['SizeOfInitializedData'] = data['Image Optional Header']['SizeOfInitializedData']
    features['SizeOfUninitializedData'] = data['Image Optional Header']['SizeOfUninitializedData']
    features['AddressOfEntryPoint'] = data['Image Optional Header']['AddressOfEntryPoint']
    features['BaseOfCode'] = data['Image Optional Header']['AddressOfEntryPoint']
    try:
        features['BaseOfData'] = data['Image Optional Header']['BaseOfData']
    except KeyError:
        features['BaseOfData'] = 0
    features['ImageBase'] = data['Image Optional Header']['ImageBase']
    features['SectionAlignment'] = data['Image Optional Header']['SectionAlignment']
    features['FileAlignment'] = data['Image Optional Header']['FileAlignment']
    osv = data['Image Optional Header']['OperatingSystemVersion'].split('.')
    features['MajorOperatingSystemVersion'] = int(osv[0])
    features['MinorOperatingSystemVersion'] = int(osv[1])
    ssv = data['Image Optional Header']['SubsystemVersion'].split('.')
    features['MajorSubsystemVersion'] = int(ssv[0])
    features['MinorSubsystemVersion'] = int(ssv[1])
    features['Subsystem'] = SUBSYSTEMS[data['Image Optional Header']['Subsystem']]
    features['DllCharacteristics'] = 0
    for char in data["Image Optional Header"]["DllCharacteristics"]:
        features['DllCharacteristics'] += DLL_CHARACTERISTICS[char]
    features['SizeOfStackReserve'] = data['Image Optional Header']['SizeofStackReserve']
    features['SizeOfStackCommit'] = data['Image Optional Header']['SizeofStackCommit']
    features['SizeOfHeapReserve'] = data['Image Optional Header']['SizeofHeapReserve']
    features['SizeOfHeapCommit'] = data['Image Optional Header']['SizeofHeapCommit']
    features['LoaderFlags'] = data['Image Optional Header']['LoaderFlags']
    features['NumberOfRvaAndSizes'] = data['Image Optional Header']['NumberOfRvaAndSizes']

    # Sections
    features['SectionsNb'] = len(data['Sections'])
    entropy = map(lambda x:x['Entropy'], data['Sections'].values())
    features['SectionsMeanEntropy'] = sum(entropy) / float(len(entropy))
    features['SectionsMinEntropy'] = min(entropy)
    features['SectionsMaxEntropy'] = max(entropy)
    raw_sizes = map(lambda x:x['SizeOfRawData'], data['Sections'].values())
    features['SectionsMeanRawsize'] = sum(raw_sizes) / float(len(raw_sizes))
    features['SectionsMinRawsize'] = min(raw_sizes)
    features['SectionsMaxRawsize'] = max(raw_sizes)
    virtual_sizes = map(lambda x:x['VirtualSize'], data['Sections'].values())
    features['SectionsMeanVirtualsize'] = sum(virtual_sizes) / float(len(virtual_sizes))
    features['SectionsMinVirtualsize'] = min(virtual_sizes)
    features['SectionsMaxVirtualsize'] = max(virtual_sizes)

    # Imports
    if 'Imports' in data.keys():
        features['ImportsNbDLL'] = len(data['Imports'])
        features['ImportsNb'] = sum(map(len, data['Imports'].values()))
    else:
        features['ImportsNbDLL'] = 0
        features['ImportsNb'] = 0

    # Resources
    if 'Resources' in data.keys():
        features['ResourcesNb'] = len(data['Resources'])
        entropy = map(lambda x:x['Entropy'], data['Resources'].values())
        features['ResourcesMeanEntropy'] = sum(entropy) / float(len(entropy))
        features['ResourcesMinEntropy'] = min(entropy)
        features['ResourcesMaxEntropy'] = max(entropy)
        sizes = map(lambda x:x['Size'], data['Resources'].values())
        features['ResourcesMeanSize'] = sum(sizes) / float(len(sizes))
        features['ResourcesMinSize'] = min(sizes)
        features['ResourcesMaxSize'] = max(sizes)
    else:
        features['ResourcesNb'] = 0
        features['ResourcesMeanEntropy'] = 0
        features['ResourcesMinEntropy'] = 0
        features['ResourcesMaxEntropy'] = 0
        features['ResourcesMeanSize'] = 0
        features['ResourcesMinSize'] = 0
        features['ResourcesMaxSize'] = 0

    if "Version Info" in data.keys():
        features['VersionInformationSize'] = len(data['Version Info'].keys())
    else:
        features['VersionInformationSize'] = 0

    return features


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Detect malicious file from manalyzer infos')
    parser.add_argument('URL', help='Manalyzer url')
    args = parser.parse_args()

    # Load classifier
    clf = joblib.load(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        'classifier/classifier.pkl'
    ))
    features = pickle.loads(open(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        'classifier/features.pkl'),
        'r').read()
    )

    if 'manalyzer.org' not in args.URL:
        print('This is not a manalyzer url')
        sys.exit(1)
    if '/report/' in args.URL:
        url = args.URL.replace('/report/', '/json/')
    else:
        url = args.URL

    data = get_data(url)
    if data == {}:
        print("Impossible to retrieve the data, quitting")
        sys.exit(1)
    else:
        # Extract the features
        data_pe = feature_extraction(data)
        pe_features = map(lambda x:data_pe[x], features)
        res= clf.predict([pe_features])[0]
        print('The file %s is %s' % (
            data_pe['md5'],
            ['malicious', 'legitimate'][res])
        )

