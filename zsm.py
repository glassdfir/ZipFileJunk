#!/usr/bin/python
#Zip seeking missile
#by Jonathan Glass and Adam Polkosnik
import sys, mmap, binascii, re, struct
from optparse import OptionParser
from datetime import datetime, date, time
from decimal import *
 
class ZipSeekingMissile:
	def __init__(self):
		self.options()
		self.openfile()

	def options(self):
		parser = OptionParser()
		parser.add_option("-f", "--file", dest="filename",help="File to carve Zips from", metavar="FILE")
		parser.add_option("-v", "--verbose", dest="verbose", action="store_true",help="Show more than file names")
		parser.add_option("-c", "--count", dest="count", action="store_true",help="Display only the counts of meta types")
		(self.options, args) = parser.parse_args()

	def openfile(self):
		if self.options.filename == None:
			print ("-f <filename> required.")
			sys.exit()
		try:
			self.filename = open(self.options.filename, "r+b")
		except:
			print ("Unable to open file: %s" % self.options.filename)
			sys.exit()
		self.look_for_local_headers()

	def look_for_local_headers(self):
		self.mm = mmap.mmap(self.filename.fileno(),0)
		self.patternLocalFileHeader = re.compile(b'\x50\x4B\x03\x04')
		self.LocalFileHeaders = [m.start() for m in self.patternLocalFileHeader.finditer(self.mm)]
		if len(self.LocalFileHeaders) < 1:
			print("No local headers found.")
		else:
			if not(self.options.count):	
				print ("Possible %d Local File Headers" % len(self.LocalFileHeaders))
			else:
				print ("Possible %d Local File Headers at offsets: %s" % (len(self.LocalFileHeaders), self.LocalFileHeaders))
				if not(self.options.count):
					for i in self.LocalFileHeaders:
						self.localfilenamelen = int(struct.unpack('<H',self.mm[i+0x1a:i+0x1c])[0])
						if self.localfilenamelen < 32767: #attempt to cut down displaying false positives. Max Windows File Path is 32767
							print("Offset %d - LH INFO - File name: %s" % (i,str(self.mm[i+0x1e:i+0x1e+self.localfilenamelen])))
							if self.options.verbose:
								self.localextrafieldlen = int(struct.unpack('<H',self.mm[i+0x1c:i+0x1e])[0])
								print("\tVersion: %.2f" % float(struct.unpack('<H',self.mm[i+0x04:i+0x06])[0]/float(10.0)))
								#Parse Flags
								print("\tCompression: %s" % self.compression_type(int(struct.unpack('<H',self.mm[i+0x08:i+0x0a])[0])))
								self.localheaderlastmodtime = int(struct.unpack('<H',self.mm[i+0x0a:i+0x0c])[0])
								self.localheaderlastmoddate = int(struct.unpack('<H',self.mm[i+0x0c:i+0x0e])[0])
								print("\tLast Modified Date %s" % self.dos_date_time_to_datetime(self.localheaderlastmoddate,self.localheaderlastmodtime))
								print("\tCRC-32 Checksum: %d" % struct.unpack('<L',self.mm[i+0x0e:i+0x12]))
								print("\tCompressed size: %d" % struct.unpack('<L',self.mm[i+0x12:i+0x16]))
								print("\tUncompressed size: %d" % struct.unpack('<L',self.mm[i+0x16:i+0x1a]))
								print("\tFile Name Length: %d" % struct.unpack('<H',self.mm[i+0x18:i+0x1a]))
								print("\tExtra Field Length: %d" % struct.unpack('<H',self.mm[i+0x1c:i+0x1e]))
								#if self.localextrafieldlen > 0:
									#print("\tExtra Field: %s" % binascii.hexlify(self.mm[i+0x30:i+0x30+self.localextrafieldlen]))
		self.look_for_central_dir_file_headers()
				
	def look_for_central_dir_file_headers(self):
		self.patternCentralDirFileHeader = re.compile(b'\x50\x4B\x01\x02')
		self.CentralDirFileHeaders = [m.start() for m in self.patternCentralDirFileHeader.finditer(self.mm)]
		if len(self.CentralDirFileHeaders) == 0:
			print("Found No Central Directory File Headers")
		else: 
			if not(self.options.count):	
				print ("Possible %d Central Directory File Headers" % len(self.CentralDirFileHeaders))
			else:
				print ("Possible %d Central Directory File Headers at offsets: %s" % (len(self.CentralDirFileHeaders), self.CentralDirFileHeaders))
				for i in self.CentralDirFileHeaders:
					# See https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html
					if (self.mm[i+0x18:i+0x1c] == 0xffffffff) or (self.mm[i+0x14:i+0x18] == 0xffffffff):
						#ZIP64 file... size is in the extra field
						self.filenamelen = int(struct.unpack('<H',self.mm[i+0x1c:i+0x1e])[0])
						self.extra=struct.unpack('<s',self.mm[i+0x2e:i+0x2e+(self.filenamelen)])
						print("Compressed size is in the extra field, implement it next" )
					else:
						self.filenamelen = int(struct.unpack('<H',self.mm[i+0x1c:i+0x1e])[0])
						if self.filenamelen < 32767:
							print("Offset %d - CD INFO - File name: %s" % (i,str(self.mm[i+0x2e:i+0x2e+self.filenamelen])))
							if self.options.verbose:
								print("\tVersion: %.2f" % float(struct.unpack('<H',self.mm[i+0x04:i+0x06])[0]/float(10.0)))
								print("\tVersion Needed To Extract: %.2f" % float(struct.unpack('<H',self.mm[i+0x06:i+0x08])[0]/float(10.0)))
								#parse flags
								print("\tCompression: %s" % self.compression_type(struct.unpack('<H',self.mm[i+0x0a:i+0x0c])[0]))
								self.lastmodtime = int(struct.unpack('<H',self.mm[i+0x0c:i+0x0e])[0])
								self.lastmoddate = int(struct.unpack('<H',self.mm[i+0x0e:i+0x10])[0])
								print("\tLast Modified Date %s" % self.dos_date_time_to_datetime(self.lastmoddate,self.lastmodtime))
								print("\tCRC-32 Checksum: %d" % struct.unpack('<L',self.mm[i+0x10:i+0x14]))
								print("\tCompressed size: %d" % struct.unpack('<L',self.mm[i+0x14:i+0x18]))
								print("\tUncompressed size: %d" % struct.unpack('<L',self.mm[i+0x18:i+0x1c]))
								print("\tFile Name Length: %d" % struct.unpack('<H',self.mm[i+0x1c:i+0x1e]))
								print("\tExtra Field Length: %d" % struct.unpack('<H',self.mm[i+0x1e:i+0x20]))
								print("\tFile Comment Length: %d" % struct.unpack('<H',self.mm[i+0x20:i+0x22]))
								print("\tDisk # Start: %d" % struct.unpack('<H',self.mm[i+0x22:i+0x24]))
		self.look_for_central_dir_end_records()
	def look_for_central_dir_end_records(self):
		self.patternCentralDirEndRecord = re.compile(b'\x50\x4B\x05\x06')
		self.CentralDirEndRecord = [m.start() for m in self.patternCentralDirEndRecord.finditer(self.mm)]
		if len(self.CentralDirEndRecord) > 0:
			print("Found %d possible hits for Central Dir. End Record at byte offsets %s ." % (len(self.CentralDirEndRecord), str(list(self.CentralDirEndRecord))))
			#Parse CD End Record
			#print("Central Dir contents: %s" % binascii.hexlify(self.mm[i:i+0x5f]))
		self.mm.close()
	def dos_date_time_to_datetime(self, dos_date, dos_time):
		secs = (dos_time & 0x1F) * 2
		mins = (dos_time & 0x7E0) >> 5
		hours = (dos_time & 0xF800) >> 11
		day = dos_date & 0x1F
		month = (dos_date & 0x1E0) >> 5
		year = ((dos_date & 0xFE00) >> 9) + 1980
		return datetime(year, month, day, hours, mins, secs)
	
	def compression_type(self,n):
		reserved = [7,11,13,15,16,17]
		if n in reserved:
			return "Reserved? Weird. Type code is %d" % n
		else:
			DictCompressionTypes ={0:"00: No Compression",1:"01: Shrunk",2:"02: reduced with compression factor 1",3:"03: reduced with compression factor 2",4:"04: reduced with compression factor 3",5:"05: reduced with compression factor 4",6:"06: imploded",8:"08: Deflated",9:"09: Enhanced Deflated",10:"10: PKWare DCL imploded",12:"12: Compressed using BZIP2",14:"14: LZMA",18:"18: compressed using IBM TERSE",19:"19: IBM LZ77 z",98:"98: PPMd version I, Rev 1"}
			if n in DictCompressionTypes:
				return DictCompressionTypes[int(n)]
			else:
				return "Undocumented Compression Type. Weird.  Type code is %d" % n
		
                                                
ZipSeekingMissile()
 