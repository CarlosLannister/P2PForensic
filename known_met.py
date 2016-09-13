# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from kaitaistruct import KaitaiStruct, KaitaiStream
import array
import cStringIO
from enum import Enum
import zlib

class KnownMet(KaitaiStruct):
    @staticmethod
    def from_file(filename):
        return KnownMet(KaitaiStream(open(filename, 'rb')))

    def __init__(self, _io, _parent = None, _root = None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self.magic = self._io.read_bytes(1)
        self.n_entries = self._io.read_u4le()
        self.file = [None] * self.n_entries
        for i in xrange(self.n_entries):
            self.file[i] = self._root.File(self._io, self, self._root)


    class File(KaitaiStruct):
        @staticmethod
        def from_file(filename):
            return File(KaitaiStream(open(filename, 'rb')))

        def __init__(self, _io, _parent = None, _root = None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.last_written = self._io.read_u4le()
            self.ed2k_hash = self._io.read_bytes(16)
            self.n_partial_hashes = self._io.read_u2le()
            self.partial_hashes = [None] * self.n_partial_hashes
            for i in xrange(self.n_partial_hashes):
                self.partial_hashes[i] = self._root.PartialHash(self._io, self, self._root)

            self.n_meta_tags = self._io.read_u4le()
            self.meta_tags = [None] * self.n_meta_tags
            for i in xrange(self.n_meta_tags):
                self.meta_tags[i] = self._root.MetaTag(self._io, self, self._root)



    class PartialHash(KaitaiStruct):
        @staticmethod
        def from_file(filename):
            return PartialHash(KaitaiStream(open(filename, 'rb')))

        def __init__(self, _io, _parent = None, _root = None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.hash = self._io.read_bytes(16)


    class MetaTag(KaitaiStruct):
        @staticmethod
        def from_file(filename):
            return MetaTag(KaitaiStream(open(filename, 'rb')))

        def __init__(self, _io, _parent = None, _root = None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.tag_type = self._root.MetaTagType(self._io.read_u1())
            self.name_length = self._io.read_bytes(2)
            self.tag_number = self._io.read_u1()
            if self.tag_type == self._root.MetaTagType.string:
                self.str_size = self._io.read_u2le()

            if self.tag_type == self._root.MetaTagType.string:
                self.str_value = self._io.read_str_byte_limit(self.str_size, "UTF-8")

            if self.tag_type == self._root.MetaTagType.integer:
                self.int_value = self._io.read_u4le()

            if self.tag_type == self._root.MetaTagType.float:
                self.float_value = self._io.read_f4le()

            if self.tag_type == self._root.MetaTagType.long_str:
                self.long_str_size = self._io.read_u4le()

            if self.tag_type == self._root.MetaTagType.long_str:
                self.long_str_value = self._io.read_str_byte_limit(self.long_str_size, "UTF-8")

            if self.tag_type == self._root.MetaTagType.uint16:
                self.uint16_value = self._io.read_u2le()

            if self.tag_type == self._root.MetaTagType.byte:
                self.byte_value = self._io.read_u1()

            if self.tag_type == self._root.MetaTagType.uint64:
                self.uint64_value = self._io.read_u8le()




    class MetaTagType(Enum):
        byte = 9
        string = 2
        long_str = 7
        integer = 3
        uint64 = 11
        uint16 = 8
        float = 4

