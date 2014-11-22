Zip Seeking Missile
==========================================

Purpose: Reads binary file for zip file headers and parses the metadata.
Usage: python zsm.py -f memdump.dmp

This tool can be used on memory dumps, pcaps, disk images, zip files, MS-Office 2007+ files (docx,xlsx...)

Usage: zsm.py [options]

Options:
  -h, --help            show this help message and exit
  -f FILE, --file=FILE  File to carve Zips from
  -v, --verbose         Show more than file names
  
C:\DEMO>python zsm.py -f "This is a test.docx"
Possible 11 Local File Headers at offsets: [0, 915, 1715, 2281, 2884, 4506, 5491, 5991, 6306, 6984, 7661]
Offset 0 - LH INFO - File name: [Content_Types].xml
Offset 915 - LH INFO - File name: _rels/.rels
Offset 1715 - LH INFO - File name: word/_rels/document.xml.rels
Offset 2281 - LH INFO - File name: word/document.xml
Offset 2884 - LH INFO - File name: word/theme/theme1.xml
Offset 4506 - LH INFO - File name: word/settings.xml
Offset 5491 - LH INFO - File name: word/fontTable.xml
Offset 5991 - LH INFO - File name: word/webSettings.xml
Offset 6306 - LH INFO - File name: docProps/app.xml
Offset 6984 - LH INFO - File name: docProps/core.xml
Offset 7661 - LH INFO - File name: word/styles.xml
Possible 11 Central Directory File Headers at offsets: [10549, 10614, 10671, 10745, 10808, 10875, 10938, 11002, 11068, 11130, 11193]
Offset 10549 - CD INFO - File name: [Content_Types].xml
Offset 10614 - CD INFO - File name: _rels/.rels
Offset 10671 - CD INFO - File name: word/_rels/document.xml.rels
Offset 10745 - CD INFO - File name: word/document.xml
Offset 10808 - CD INFO - File name: word/theme/theme1.xml
Offset 10875 - CD INFO - File name: word/settings.xml
Offset 10938 - CD INFO - File name: word/fontTable.xml
Offset 11002 - CD INFO - File name: word/webSettings.xml
Offset 11068 - CD INFO - File name: docProps/app.xml
Offset 11130 - CD INFO - File name: docProps/core.xml
Offset 11193 - CD INFO - File name: word/styles.xml
Found 1 hits for Central Dir. End Record at byte offsets [11254] .

C:\Users\jon\Documents\GitHub\ZipFileJunk>python zsm.py -f "c:\demo\zip\File1.zip" -v
Possible 3 Local File Headers at offsets: [0, 64, 128]
Offset 0 - LH INFO - File name: File1.txt
        Version: 2.00
        Compression: 08: Deflated
        Last Modified Date 2014-11-13 22:31:28
        CRC-32 Checksum: 751451497
        Compressed size: 25
        Uncompressed size: 40
        File Name Length: 0
        Extra Field Length: 0
Offset 64 - LH INFO - File name: File2.txt
        Version: 2.00
        Compression: 08: Deflated
        Last Modified Date 2014-11-13 22:31:16
        CRC-32 Checksum: 2035682662
        Compressed size: 25
        Uncompressed size: 40
        File Name Length: 0
        Extra Field Length: 0
Offset 128 - LH INFO - File name: File3.txt
        Version: 2.00
        Compression: 08: Deflated
        Last Modified Date 2014-11-02 23:47:04
        CRC-32 Checksum: 1924788770
        Compressed size: 22
        Uncompressed size: 23
        File Name Length: 0
        Extra Field Length: 0
Possible 3 Central Directory File Headers at offsets: [189, 244, 299]
Offset 189 - CD INFO - File name: File1.txt
        Version: 2.00
        Version Needed To Extract: 2.00
        Compression: 08: Deflated
        Last Modified Date 2014-11-13 22:31:28
        CRC-32 Checksum: 751451497
        Compressed size: 25
        Uncompressed size: 40
        File Name Length: 9
        Extra Field Length: 0
        File Comment Length: 0
        Disk # Start: 0
Offset 244 - CD INFO - File name: File2.txt
        Version: 2.00
        Version Needed To Extract: 2.00
        Compression: 08: Deflated
        Last Modified Date 2014-11-13 22:31:16
        CRC-32 Checksum: 2035682662
        Compressed size: 25
        Uncompressed size: 40
        File Name Length: 9
        Extra Field Length: 0
        File Comment Length: 0
        Disk # Start: 0
Offset 299 - CD INFO - File name: File3.txt
        Version: 2.00
        Version Needed To Extract: 2.00
        Compression: 08: Deflated
        Last Modified Date 2014-11-02 23:47:04
        CRC-32 Checksum: 1924788770
        Compressed size: 22
        Uncompressed size: 23
        File Name Length: 9
        Extra Field Length: 0
        File Comment Length: 0
        Disk # Start: 0
Found 1 hits for Central Dir. End Record at byte offsets [354] .