#!/usr/bin/python
#Zip seeking missile
# Reads file for Central Directory Header 50 4B 05 06
# Record the disk offset of the Central Directory
# Seek 16 bytes and read 4 (Offset of cd wrt to starting disk)
# Seek to disk offset of (Start of the Central Directory Header - offset of the disk) which should be the start of the zip file if it is all in one piece.
#Read 4 bytes and check for a Local File Header 50 4B 03 04
#If it is there then we can *assume* that this is a complete zip file. Save it to disk.

# def parse_local_file_header(raw_record, options):
# def parse_central_dir_file_header(raw_record, options):
# def parse_end_of_central_dir_record(raw_record, options):
import sys, mmap, binascii, re, struct
from optparse import OptionParser
from datetime import datetime, date, time
 
class ZipSeekingMissile:
	def __init__(self):
		self.options()
		self.openfile()

	def options(self):
		parser = OptionParser()
		parser.add_option("-f", "--file", dest="filename",help="File to carve Zips from", metavar="FILE")
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
			for i in reversed(self.LocalFileHeaders):
				self.localfilenamelen = int(struct.unpack('<H',self.mm[i+0x1a:i+0x1c])[0])
				self.localextrafieldlen = int(struct.unpack('<H',self.mm[i+0x1c:i+0x1e])[0])
				print("File name: %s" % str(self.mm[i+0x1e:i+0x1e+self.localfilenamelen]))
				print("\tVersion: %d" % int(struct.unpack('<H',self.mm[i+0x04:i+0x06])[0]))
				#Parse Flags
				print("\tCompression: %d" % int(struct.unpack('<H',self.mm[i+0x08:i+0x0a])[0]))
				self.localheaderlastmodtime = int(struct.unpack('<H',self.mm[i+0x0a:i+0x0c])[0])
				self.localheaderlastmoddate = int(struct.unpack('<H',self.mm[i+0x0c:i+0x0e])[0])
				print("\tLast Modified Date %s" % self.dos_date_time_to_datetime(self.localheaderlastmoddate,self.localheaderlastmodtime))
				print("\tCRC-32 Checksum: %d" % struct.unpack('<L',self.mm[i+0x0e:i+0x12]))
				print("\tCompressed size: %d" % struct.unpack('<L',self.mm[i+0x12:i+0x16]))
				print("\tUncompressed size: %d" % struct.unpack('<L',self.mm[i+0x16:i+0x1a]))
				print("\tFile Name Length: %d" % struct.unpack('<H',self.mm[i+0x18:i+0x1a]))
				print("\tExtra Field Length: %d" % struct.unpack('<H',self.mm[i+0x1c:i+0x1e]))
				if self.localextrafieldlen > 0:
					print("\tExtra Field: %s" % binascii.hexlify(self.mm[i+0x30:i+0x30+self.localextrafieldlen]))
		self.look_for_central_dir()
				
	def look_for_central_dir(self):
		self.patternCentralDirFileHeader = re.compile(b'\x50\x4B\x01\x02')
		self.CentralDirFileHeaders = [m.start() for m in self.patternCentralDirFileHeader.finditer(self.mm)]
		self.patternCentralDirEndRecord = re.compile(b'\x50\x4B\x05\x06')
		self.CentralDirEndRecord = [m.start() for m in self.patternCentralDirEndRecord.finditer(self.mm)]
		print ("Possible %d Central Dir offsets: %s" % (len(self.CentralDirFileHeaders), self.CentralDirFileHeaders))
		if len(self.CentralDirEndRecord) > 0:
			print("Found %d hits for Central Dir. End Record at byte offsets %s ." % (len(self.CentralDirEndRecord), str(list(self.CentralDirEndRecord))))
		if len(self.CentralDirFileHeaders) < 1:
			print("Found Central Directory End Record but no Central Directory File Headers? Corruption?")
			sys.exit()
		else: 
			for i in reversed(self.CentralDirFileHeaders):
				# See https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html
				if (self.mm[i+0x18:i+0x1c] == 0xffffffff) or (self.mm[i+0x14:i+0x18] == 0xffffffff):
					#ZIP64 file... size is in the extra field
					self.filenamelen = int(struct.unpack('<H',self.mm[i+0x1c:i+0x1e])[0])
					self.extra=struct.unpack('<s',self.mm[i+0x2e:i+0x2e+(self.filenamelen)])
					print("Compressed size is in the extra field, implement it next" )
				else:
					self.filenamelen = int(struct.unpack('<H',self.mm[i+0x1c:i+0x1e])[0])
					print("File name: %s" % str(self.mm[i+0x2e:i+0x2e+self.filenamelen]))
					print("\tVersion: %d" % int(struct.unpack('<H',self.mm[i+0x04:i+0x06])[0]))
					print("\tVersion Needed To Extract: %d" % struct.unpack('<H',self.mm[i+0x06:i+0x08]))
					print("\tCompression Type: %d" % struct.unpack('<H',self.mm[i+0x0a:i+0x0c]))
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
                                                
ZipSeekingMissile()
 