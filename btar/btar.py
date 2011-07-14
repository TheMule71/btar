#!/usr/bin/env python

import sys
import os
import struct
try:
    from hashlib import sha1, md5
except ImportError:
    from sha import sha as sha1
    from md5 import md5
import zlib

try:
    import crcmod
    try:
        crc32 = crcmod.mkCrcFun(0x04c11db7, 0x00000000, True, 0xffffffff)
    except ValueError:
        # NOTE, crcmod reports "The degree of the polynomial must be 8, 16,
        # 24, 32 or 64". Patched to export the internal function that
        # doesn't check the parameters. The generated table is the same
        # you can find in bacula source code for their crc32 function.
        # It seems they are fine with the polynomial not being of the
        # right degree. The polynomial is bit-reversed, that's why it looks
        # different: 0xedb88320 == 0b11101101101110001000001100100000,
        # 0x04c11db7 == 0b00000100110000010001110110110111.
        crc32, CRC_TABLE = crcmod._mkCrcFun(0x04c11db7, 32, 0x00000000,
                                            True, 0xffffffff)
except ImportError, NameError:
    # our pure python porting of bacula code - this is quite slow
    # You'd better install and patch the crcmod module, really.
    # The following code is almost line-by-line port of the bacula C code.
    CRC_TABLE = []
    for i in range(256):
        crc = i
        for j in range(8):
            if crc & 1:
                crc = 0xedb88320 ^ (crc >> 1)
            else:
                crc = crc >> 1
        CRC_TABLE.append(crc)

    def crc32(data):
        crc = 0xffffffff;
        for c in data:
            crc = CRC_TABLE[(crc ^ ord(c)) & 0xff] ^ (crc >> 8)
        return crc ^ 0xffffffff
    print "CRC32, using pure python function"

# Dump the table to compare with the source of bacula
#n = 0
#for x in CRC_TABLE:
#    print "0x%08x" % (x,),
#    n += 1
#    if n == 5:
#        print
#        n = 0


# this is stripped from the C header file
_foo = """STREAM_NONE                         0
STREAM_UNIX_ATTRIBUTES              1
STREAM_FILE_DATA                    2
STREAM_MD5_SIGNATURE                3
STREAM_MD5_DIGEST                   3
STREAM_GZIP_DATA                    4
STREAM_UNIX_ATTRIBUTES_EX           5
STREAM_SPARSE_DATA                  6
STREAM_SPARSE_GZIP_DATA             7
STREAM_PROGRAM_NAMES                8
STREAM_PROGRAM_DATA                 9
STREAM_SHA1_SIGNATURE              10
STREAM_SHA1_DIGEST                 10
STREAM_WIN32_DATA                  11
STREAM_WIN32_GZIP_DATA             12
STREAM_MACOS_FORK_DATA             13
STREAM_HFSPLUS_ATTRIBUTES          14
STREAM_UNIX_ACCESS_ACL             15
STREAM_UNIX_DEFAULT_ACL            16
STREAM_SHA256_DIGEST               17
STREAM_SHA512_DIGEST               18
STREAM_SIGNED_DIGEST               19
STREAM_ENCRYPTED_FILE_DATA         20
STREAM_ENCRYPTED_WIN32_DATA        21
STREAM_ENCRYPTED_SESSION_DATA      22
STREAM_ENCRYPTED_FILE_GZIP_DATA    23
STREAM_ENCRYPTED_WIN32_GZIP_DATA   24
STREAM_ENCRYPTED_MACOS_FORK_DATA   25
STREAM_PLUGIN_NAME                 26
STREAM_PLUGIN_DATA                 27
STREAM_RESTORE_OBJECT              28
STREAM_COMPRESSED_DATA                 29
STREAM_SPARSE_COMPRESSED_DATA          30
STREAM_WIN32_COMPRESSED_DATA           31
STREAM_ENCRYPTED_FILE_COMPRESSED_DATA  32
STREAM_ENCRYPTED_WIN32_COMPRESSED_DATA 33
STREAM_ACL_AIX_TEXT              1000
STREAM_ACL_DARWIN_ACCESS_ACL     1001
STREAM_ACL_FREEBSD_DEFAULT_ACL   1002
STREAM_ACL_FREEBSD_ACCESS_ACL    1003
STREAM_ACL_HPUX_ACL_ENTRY        1004
STREAM_ACL_IRIX_DEFAULT_ACL      1005
STREAM_ACL_IRIX_ACCESS_ACL       1006
STREAM_ACL_LINUX_DEFAULT_ACL     1007
STREAM_ACL_LINUX_ACCESS_ACL      1008
STREAM_ACL_TRU64_DEFAULT_ACL     1009
STREAM_ACL_TRU64_DEFAULT_DIR_ACL 1010
STREAM_ACL_TRU64_ACCESS_ACL      1011
STREAM_ACL_SOLARIS_ACLENT        1012
STREAM_ACL_SOLARIS_ACE           1013
STREAM_ACL_AFS_TEXT              1014
STREAM_ACL_AIX_AIXC              1015
STREAM_ACL_AIX_NFS4              1016
STREAM_ACL_FREEBSD_NFS4_ACL      1017
STREAM_XATTR_IRIX                1990
STREAM_XATTR_TRU64               1991
STREAM_XATTR_AIX                 1992
STREAM_XATTR_OPENBSD             1993
STREAM_XATTR_SOLARIS_SYS         1994
STREAM_XATTR_SOLARIS             1995
STREAM_XATTR_DARWIN              1996
STREAM_XATTR_FREEBSD             1997
STREAM_XATTR_LINUX               1998
STREAM_XATTR_NETBSD              1999"""

stream_types = {}
for l in _foo.split("\n"):
    v, k = l.split()
    stream_types[int(k)] = v
    # NOTE Pollute the global space with the definitions
    globals()[v] = int(k)
del _foo, v, k

def stream_to_str(n):
    cont = ""
    if n < 0:
        cont = "cont"
        n = -n
    return cont + stream_types.get(n, str(n))

#########

# Ported from Bacula C code
# An Attributes record consists of:
#  File_index
#  Type   (FT_types)
#  Filename
#  Attributes
#  Link name (if file linked i.e. FT_LNK)
#  Extended attributes (Win32)
# plus optional values determined by AR_ flags in upper bits of Type
#  Data_stream

_foo = """FT_MASK       65535
FT_LNKSAVED   1
FT_REGE       2
FT_REG        3
FT_LNK        4
FT_DIREND     5
FT_SPEC       6
FT_NOACCESS   7
FT_NOFOLLOW   8
FT_NOSTAT     9
FT_NOCHG     10
FT_DIRNOCHG  11
FT_ISARCH    12
FT_NORECURSE 13
FT_NOFSCHG   14
FT_NOOPEN    15
FT_RAW       16
FT_FIFO      17
FT_DIRBEGIN  18
FT_INVALIDFS 19
FT_INVALIDDT 20
FT_REPARSE   21
FT_PLUGIN    22
FT_DELETED   23
FT_BASE      24
FT_RESTORE_FIRST 25
FT_JUNCTION  26
AR_DATA_STREAM 65536"""

file_types = {}
for l in _foo.split("\n"):
    v, k = l.split()
    if not v == "FT_MASK":
        file_types[int(k)] = v
    # NOTE Pollute the global space with the definitions
    globals()[v] = int(k)
del _foo, v, k


BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def from_base64(s):
    """Bacula's idea of base64 (totally non standard)"""

    negative = (s[0] == "-")
    if negative:
        s = s[1:]
    val = 0
    i = 0
    while i < len(s) and s[i] != " ":
        val <<= 6
        try:
            val += BASE64_CHARS.index(s[i]) 
        except ValueError:
            print "s=%s, i=%d, s[i]=%s" % (repr(s), i, s[i])
            raise
        i += 1
    if negative:
        val = -val
    return val, i

class Attributes(object):
    def __init__(self, file_index, _type, data_stream, fname, attr, lname,
                                                    attrEx, delta_seq):
        self.file_index = file_index
        self.type = _type
        self.data_stream = data_stream
        self.fname = fname
        self.attr = attr
        self.lname = lname
        self.attrEx = attrEx
        self.delta_seq = delta_seq

    def __str__(self):
        return """Attributes:
 file_index = %s
 type = %s
 data_stream = %s
 fname = %s
 attr = %s
 (dev, ino, mode, nlink, uid, gid, rdev, size, blksize, blocks, atime, mtime, ctime, LinkFI, flags, dstid)
 lname = %s
 attrEx = %s
 delta_seq = %s""" % tuple(repr(x) for x in (self.file_index,
        file_types[self.type], self.data_stream, self.fname, self.attr,
        
        self.lname, self.attrEx, self.delta_seq))

    def decode_stat(self):
        return self.attr.split()

    @classmethod
    def unpack_attributes_record(cls, data):
        #print "unpack_attributes_record:", repr(data)
        rest = data
        file_index, rest = rest.split(" ", 1)
        file_index = int(file_index)
        _type, rest = rest.split(" ", 1)
        _type = int(_type)
        data_stream = _type & AR_DATA_STREAM
        _type &= FT_MASK
        fname, rest = rest.split("\0", 1)
        attr, rest = rest.split("\0", 1)

        # parsing the stat structure
        attr = [from_base64(x)[0] for x in attr.split()]
        attr[-1] = stream_types[attr[-1]]

        lname, rest = rest.split("\0", 1)
        if _type == FT_RESTORE_FIRST:
            attrEx = rest
        else:
            attrEx, rest = rest.split("\0", 1)
            if data_stream:
                b64 = re.split(" |\0", rest, 1)
                negative = (b64[0] == "-")
                if negative:
                    b64 = b64[1:]
                data_stream = b64.decode("base64")
                if negative:
                    data_stream = -data_stream
            else:
                #attrEx, rest = rest.split("\0", 1)
                if len(rest):
                    #print "rest =", repr(rest)
                    delta_seq, rest = rest.split("\0", 1)
                    delta_seq = int(delta_seq)
                else:
                    delta_seq = 0

        return cls(file_index, _type, data_stream, fname, attr, lname,
                                                    attrEx, delta_seq)

#########

#                   Record Header Format BB02
#    :=======================================================:
#    |              FileIndex        (int32_t)               |
#    |-------------------------------------------------------|
#    |              Stream           (int32_t)               |
#    |-------------------------------------------------------|
#    |              DataSize         (uint32_t)              |
#    :=======================================================:

BB02_RECORD_H_FMT = "!iiI"
PRE_LABEL = -1
VOL_LABEL = -2
EOM_LABEL = -3
SOS_LABEL = -4
EOS_LABEL = -5
EOT_LABEL = -6
SOB_LABEL = -7
EOB_LABEL = -8

def parse_string(data, offset):
    out = []
    while offset < len(data):
        c = data[offset]
        if c == "\0":
            return "".join(out), offset+1
        out.append(c)
        offset += 1

class VolumeLabel(object):
    def __init__(self, data):
        offset = 0
        out = []
        self.Id, offset = parse_string(data, offset)
        l = struct.calcsize("!I")
        self.VerNum = struct.unpack("!I", data[offset:offset+l])[0]
        offset += l
        if self.VerNum >= 11:
            l = struct.calcsize("!QQdd")
            self.label_btime, self.write_btime, self.write_date, self.write_time = \
                struct.unpack("!QQdd", data[offset:offset+l])
        else:
            l = struct.calcsize("!dddd")
            self.label_date, self.label_time, self.write_date, self.write_time = \
                struct.unpack("!dddd", data[offset:offset+l])
        offset += l
        self.VolumeName, offset = parse_string(data, offset)
        self.PrevVolumeName, offset = parse_string(data, offset)
        self.PoolName, offset = parse_string(data, offset)
        self.PoolType, offset = parse_string(data, offset)
        self.MediaType, offset = parse_string(data, offset)
        self.HostName, offset = parse_string(data, offset)
        self.LabelProg, offset = parse_string(data, offset)
        self.ProgVersion, offset = parse_string(data, offset)
        self.ProgDate, self.offset = parse_string(data, offset)

    def __str__(self):
        return """Volume Label:
 Id: %s
 VerNum: %d
 label_time: %d
 write_time: %d
 VolumeName: %s
 PrevVolumeName: %s
 PoolName: %s
 PoolType: %s
 MediaType: %s
 HostName: %s
 LabelProg: %s
 ProvVersion: %s
 ProgDate: %s""" % (repr(self.Id), self.VerNum, self.label_btime,
    self.write_btime, self.VolumeName, self.PrevVolumeName, self.PoolName,
    self.PoolType, self.MediaType, self.HostName, self.LabelProg,
    self.ProgVersion, self.ProgDate)

class SOSLabel(object):
    def __init__(self, data):
        offset = 0
        self.Id, offset = parse_string(data, offset)
        l = struct.calcsize("!II")
        self.VerNum, self.JobId = struct.unpack("!II", data[offset:offset+l])
        offset += l
        if self.VerNum >= 11:
            l = struct.calcsize("!Qd")
            self.write_btime, self.write_time = struct.unpack("!Qd",
                                                    data[offset:offset+l])
        else:
            l = struct.calcsize("!dd")
            self.write_date, self.write_time = struct.unpack("!dd",
                                                    data[offset:offset+l])
        offset += l
        self.PoolName, offset = parse_string(data, offset)
        self.PoolType, offset = parse_string(data, offset)
        self.JobName, offset = parse_string(data, offset)
        self.ClientName, offset = parse_string(data, offset)
        if self.VerNum >= 10:
            self.Job, offset = parse_string(data, offset)
            self.FileSetName, offset = parse_string(data, offset)
            l = struct.calcsize("!II")
            self.JobType, self.JobLevel = struct.unpack("!II",
                                                    data[offset:offset+l])
            offset += l
        if self.VerNum >= 11:
            self.FileSetMD5, offset = parse_string(data, offset)
        self.offset = offset

    def __str__(self):
        return """Session Label:
 Id: %s
 VerNum: %s
 JobId: %s
 write_btime: %s
 write_time: %s
 PoolName: %s
 PoolType: %s
 JobName: %s
 ClientName: %s
 Job: %s
 FileSetName: %s
 JobType: %s
 JobLevel: %s
 FileSetMD5: %s""" % tuple([repr(x) for x in (self.Id, self.VerNum,
    self.JobId, self.write_btime, self.write_time, self.PoolName, self.PoolType,
    self.JobName, self.ClientName, self.Job, self.FileSetName, self.JobType,
    self.JobLevel, self.FileSetMD5)])

class EOSLabel(SOSLabel):
    def __init__(self, data):
        super(EOSLabel, self).__init__(data)
        self.JobFiles = self.JobBytes = self.StartBlock = self.EndBlock = \
        self.StartFile = self.EndFile = self.JobErrors = self.JobStatus = 0
        if self.VerNum >= 11:
            l = struct.calcsize("!IQIIIIII")
            self.JobFiles, self.JobBytes, self.StartBlock, self.EndBlock, \
            self.StartFile, self.EndFile, self.JobErrors, self.JobStatus \
                = struct.unpack("!IQIIIIII", data[self.offset:self.offset+l])
        else:
            l = struct.calcsize("!IQIIIII")
            self.JobFiles, self.JobBytes, self.StartBlock, self.EndBlock, \
            self.StartFile, self.EndFile, self.JobErrors \
                = struct.unpack("!IQIIIII", data[self.offset:self.offset+l])
            JS_Terminated = "T"
            self.JobStatus = JS_Terminated
        self.offset += l

    def __str__(self):
        sos_str = super(EOSLabel, self).__str__()
        return sos_str + """
 JobFiles: %s
 JobBytes: %s
 StartBlock: %s
 EndBlock: %s
 StartFile: %s
 EndFile: %s
 JobErrors: %s
 JobStatus: %s""" % tuple([repr(x) for x in (self.JobFiles, self.JobBytes,
    self.StartBlock, self.EndBlock, self.StartFile, self.EndFile,
    self.JobErrors, self.JobStatus)])


class Record(object):
    def __init__(self, data=None):
        self.header = None
        self.data = data
        self.partial = False
        self.label = None
        self.attributes = None
        self.valid = False
        self.parse()

    def parse(self):
        self.partial = False
        hsize = struct.calcsize(BB02_RECORD_H_FMT)
        if len(self.data) < hsize:
            self.valid = False
            print "Record: short header!"
            return

        header_bin = self.data[:hsize]
        self.header = self.parse_header(header_bin)

        if self.header[0] == EOM_LABEL:
            self.label = "EOM_LABEL"
        if self.header[0] == PRE_LABEL:
            self.label = "PRE_LABEL"
        if self.header[0] == VOL_LABEL:
            self.label = VolumeLabel(self.data[hsize:])
        if self.header[0] == SOS_LABEL:
            self.label = SOSLabel(self.data[hsize:])
        if self.header[0] == EOS_LABEL:
            self.label = EOSLabel(self.data[hsize:])
        if self.header[0] == EOT_LABEL:
            self.label = "EOT_LABEL"
        if self.header[0] == SOB_LABEL:
            self.label = "SOB_LABEL"
        if self.header[0] == EOB_LABEL:
            self.label = "EOB_LABEL"

        if len(self.data) < (hsize + self.header[2]):
            self.partial = True

        self.data = self.data[hsize:hsize+self.header[2]]

        # further parsing may fail if we're a partial record
        if self.partial:
            return

        if self.header.FileIndex < 0:
            return

    def __repr__(self):
        data_str = None
        if self.data:
            data_str = self.data[:32]
        return "%s(%s, %s)" % (self.__class__.__name__, repr(self.header), repr(data_str))

    def __str__(self):
        h = list(self.header)
        h1l = "st"
        if h[0] < 0:
            h1l = "jid"
            h[1] = str(h[1])
        else:
            h[1] = stream_to_str(h[1])
        ret = self.__class__.__name__ + ": fi=%d, %s=%s, ds=%s" % (h[0], h1l, h[1], h[2])
        
        if self.label:
            ret += "\n"+str(self.label)
            return ret
        if self.header.Stream == STREAM_UNIX_ATTRIBUTES:
            self.attributes = Attributes.unpack_attributes_record(self.data)
            ret += "\n"+str(self.attributes)
        if self.header.Stream == STREAM_SHA1_DIGEST:
            ret += "\nData: " +  self.data.encode("hex")
        if self.header.Stream == STREAM_MD5_DIGEST:
            ret += "\nData: " +  self.data.encode("hex")
        return ret
        
    def __len__(self):
        if not self.header:
            return 0
        if not self.data:
            return struct.calcsize(BB02_RECORD_H_FMT)
        return struct.calcsize(BB02_RECORD_H_FMT) + len(self.data)

    @staticmethod
    def parse_header(rec_bin):
        class record_header(list):
            def __init__(self, l):
                self.extend(l)
                self.FileIndex = self[0]
                self.Stream = self[1]
                self.DataSize = self[2]
        return record_header(struct.unpack(BB02_RECORD_H_FMT, rec_bin))

# BB02 Block Header
#   uint32_t CheckSum;        /* Block check sum */
#   uint32_t BlockSize;       /* Block byte size including the header */
#   uint32_t BlockNumber;     /* Block number */
#   char ID[4] = "BB02";      /* Identification and block level */
#   uint32_t VolSessionId;    /* Applies to all records  */
#   uint32_t VolSessionTime;  /*   contained in this block */
BB02_HEADER_FMT = "!III4sII"

class Block(object):
    def __init__(self, header=None, data=None):
        self.header = header
        self.data = data

    def __repr__(self):
        data_str = None
        if self.data:
            data_str = self.data[:32]
        return "%s(%s, %s)" % (self.__class__.__name__, repr(self.header), repr(data_str))

    def __str__(self):
        return "Block: cs=0x%08x, bs=%d, bn=%d, ID=%s, VSID=%d, VSTM=%d" % self.header

    @classmethod
    def from_file(cls, f, offset=0):
        if offset:
            f.seek(offset, os.SEEK_CUR)
        hsize = struct.calcsize(BB02_HEADER_FMT)
        header_bin = f.read(hsize)
        if len(header_bin) != hsize:
            return None
        header = cls.parse_header(header_bin)
        if header[3] != "BB02":
            return None
        data = f.read(header[1] - struct.calcsize(BB02_HEADER_FMT))
        if (len(header_bin) + len(data) != header[1]):
            return None
        crc = crc32(header_bin[4:] + data) & 0xffffffff
        if header[0] != crc:
            print "CRC Failed: 0x%08x != 0x%08x" % (header[0], crc)
            return None
        return cls(header, data)

    @staticmethod
    def parse_header(header_bin):
        return struct.unpack(BB02_HEADER_FMT, header_bin)


class VolumeList(object):
    def __init__(self, volumes):
        print "Volumes:", volumes
        self.volumes = volumes
        self.b = None
        self.offset = None
        self.findex = 0
        self.file = None

    def __iter__(self):
        return self

    def next(self):
        r = self.read_record()
        if not r:
            raise StopIteration
        return r

    def read_block(self):
        if self.findex >= len(self.volumes):
            return None
        if not self.file:
            if self.volumes[self.findex] == "-":
                self.file = sys.stdin
            else:
                print "Opening volume %d %s" % (self.findex, self.volumes[self.findex])
                self.file = open(self.volumes[self.findex])
        b = Block.from_file(self.file)
        if b:
            return b
        self.file.close()
        self.file = None
        self.findex += 1
        return self.read_block()

    def read_record(self):
        if self.b and 0 < (len(self.b.data) - self.offset) < struct.calcsize(BB02_RECORD_H_FMT):
            # sanity check, this should never happen!
            print "WARNING: garbage at the end of block: len(b.data) = %d, offset = %d" % (len(self.b.data), self.offset)
            self.offset = len(self.b.data)
        
        if not self.b or len(self.b.data) == self.offset:
            # no block or end of block
            self.b = self.read_block()
            self.offset = 0
        if not self.b:
            return None

        r = Record(self.b.data[self.offset:])
        self.offset += len(r)

        if r.header.FileIndex == VOL_LABEL:
            print r
            self.vollabel = r.label
            return self.read_record()

        if not r.partial:
            return r

        # partial record
        r2 = self.read_record()
        if not r2:
            return None
        
        if r.header.Stream > 0:
            assert r2.header.Stream == -r.header.Stream
        else:
            assert r2.header.Stream == r.header.Stream
        r.data += r2.data
        assert not r2.partial
        assert len(r.data) == r.header.DataSize
        r.partial = False
        return r


if __name__ == "__main__":
    vl = VolumeList(sys.argv[1:])

    fi = -1
    skip_fi = None
    offset = 0
    out_offset = 0
    sha1_sig = sha1()
    md5_sig = md5()
    for r in vl:
        print r

        if r.header.FileIndex == SOS_LABEL:
            skip_fi = None
            fi = -1

        if (r.header.FileIndex == skip_fi):
            print "skipping..."
            continue

        if r.header.FileIndex < 0:
            continue

        stream = r.header.Stream

        if fi == -1 and stream < 0:
            skip_fi = r.header.FileIndex
            continue

        if (stream < 0):
            stream = - stream

        if stream == STREAM_SHA1_DIGEST:
            if r.data != sha1_sig.digest():
                print "SHA1: FAILED %s / %s" % tuple(x.encode("hex") for x in (r.data, sha1_sig.digest()))
            else:
                print "SHA1: %s VERIFIED" % (r.data.encode("hex"))
            continue
        if stream == STREAM_MD5_DIGEST:
            if r.data != md5_sig.digest():
                print "MD5: FAILED %s / %s" % tuple(x.encode("hex") for x in (r.data, md5_sig.digest()))
            else:
                print "MD5: %s VERIFIED" % (r.data.encode("hex"))
            continue

        if r.header.FileIndex != fi:
            sha1_sig = sha1()
            md5_sig = md5()
            fi = r.header.FileIndex
            skip_fi = None
            out_offset = 0

        if stream not in (STREAM_SPARSE_GZIP_DATA, STREAM_GZIP_DATA, STREAM_SPARSE_DATA, STREAM_FILE_DATA):
            print "r.header.Stream = %s, ignoring data" % (stream_types[stream])
            continue

        data = r.data
        # XXX sparse
        if stream in (STREAM_SPARSE_GZIP_DATA, STREAM_SPARSE_DATA):
            offset = struct.unpack("!Q", data[:struct.calcsize("!Q")])[0]
            #print "offset = %ld, out_offset = %ld" % (offset, out_offset)
            #assert offset == out_offset
            data = data[struct.calcsize("!Q"):]

        if stream in (STREAM_SPARSE_GZIP_DATA, STREAM_GZIP_DATA):
            try:
                data = zlib.decompress(data)
            except zlib.error, e:
                print e

        out_offset += len(data)
        sha1_sig.update(data)
        md5_sig.update(data)
