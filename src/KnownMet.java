// This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import io.kaitai.struct.KaitaiStruct;
import io.kaitai.struct.KaitaiStream;

import java.io.IOException;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class KnownMet extends KaitaiStruct {
    public static KnownMet fromFile(String fileName) throws IOException {
        return new KnownMet(new KaitaiStream(fileName));
    }

    public KnownMet(KaitaiStream _io) throws IOException {
        super(_io);
        this._root = this;
        _parse();
    }

    public KnownMet(KaitaiStream _io, KaitaiStruct _parent) throws IOException {
        super(_io);
        this._parent = _parent;
        this._root = this;
        _parse();
    }

    public KnownMet(KaitaiStream _io, KaitaiStruct _parent, KnownMet _root) throws IOException {
        super(_io);
        this._parent = _parent;
        this._root = _root;
        _parse();
    }
    private void _parse() throws IOException {
        this.magic = _io.readBytes(1);
        this.nEntries = _io.readU4le();
        entries = new ArrayList<Entry>((int) (nEntries()));
        for (int i = 0; i < nEntries(); i++) {
            this.entries.add(new Entry(_io, this, _root));
        }
    }
    public static class Entry extends KaitaiStruct {
        public static Entry fromFile(String fileName) throws IOException {
            return new Entry(new KaitaiStream(fileName));
        }

        public Entry(KaitaiStream _io) throws IOException {
            super(_io);
            _parse();
        }

        public Entry(KaitaiStream _io, KnownMet _parent) throws IOException {
            super(_io);
            this._parent = _parent;
            _parse();
        }

        public Entry(KaitaiStream _io, KnownMet _parent, KnownMet _root) throws IOException {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _parse();
        }
        private void _parse() throws IOException {
            this.lastWritten = _io.readU4le();
            this.ed2kHash = _io.readBytes(16);
            this.nPartialHashes = _io.readU2le();
            partialHashes = new ArrayList<PartialHash>((int) (nPartialHashes()));
            for (int i = 0; i < nPartialHashes(); i++) {
                this.partialHashes.add(new PartialHash(_io, this, _root));
            }
            this.nMetaTags = _io.readU4le();
            metaTags = new ArrayList<MetaTag>((int) (nMetaTags()));
            for (int i = 0; i < nMetaTags(); i++) {
                this.metaTags.add(new MetaTag(_io, this, _root));
            }
        }
        private long lastWritten;
        private byte[] ed2kHash;
        private int nPartialHashes;
        private ArrayList<PartialHash> partialHashes;
        private long nMetaTags;
        private ArrayList<MetaTag> metaTags;
        private KnownMet _root;
        private KnownMet _parent;
        public long lastWritten() { return lastWritten; }
        public byte[] ed2kHash() { return ed2kHash; }
        public int nPartialHashes() { return nPartialHashes; }
        public ArrayList<PartialHash> partialHashes() { return partialHashes; }
        public long nMetaTags() { return nMetaTags; }
        public ArrayList<MetaTag> metaTags() { return metaTags; }
        public KnownMet _root() { return _root; }
        public KnownMet _parent() { return _parent; }
    }
    public static class PartialHash extends KaitaiStruct {
        public static PartialHash fromFile(String fileName) throws IOException {
            return new PartialHash(new KaitaiStream(fileName));
        }

        public PartialHash(KaitaiStream _io) throws IOException {
            super(_io);
            _parse();
        }

        public PartialHash(KaitaiStream _io, Entry _parent) throws IOException {
            super(_io);
            this._parent = _parent;
            _parse();
        }

        public PartialHash(KaitaiStream _io, Entry _parent, KnownMet _root) throws IOException {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _parse();
        }
        private void _parse() throws IOException {
            this.hash = _io.readBytes(16);
        }
        private byte[] hash;
        private KnownMet _root;
        private KnownMet.Entry _parent;
        public byte[] hash() { return hash; }
        public KnownMet _root() { return _root; }
        public KnownMet.Entry _parent() { return _parent; }
    }
    public static class MetaTag extends KaitaiStruct {
        public static MetaTag fromFile(String fileName) throws IOException {
            return new MetaTag(new KaitaiStream(fileName));
        }

        public MetaTag(KaitaiStream _io) throws IOException {
            super(_io);
            _parse();
        }

        public MetaTag(KaitaiStream _io, Entry _parent) throws IOException {
            super(_io);
            this._parent = _parent;
            _parse();
        }

        public MetaTag(KaitaiStream _io, Entry _parent, KnownMet _root) throws IOException {
            super(_io);
            this._parent = _parent;
            this._root = _root;
            _parse();
        }
        private void _parse() throws IOException {
            this.tagType = MetaTagType.byId(_io.readU1());
            this.nameLength = _io.readBytes(2);
            this.tagNumber = _io.readU1();
            if (tagType() == MetaTagType.STRING) {
                this.strSize = _io.readU2le();
            }
            if (tagType() == MetaTagType.STRING) {
                this.strValue = _io.readStrByteLimit(strSize(), "UTF-8");
            }
            if (tagType() == MetaTagType.INTEGER) {
                this.intValue = _io.readU4le();
            }
            if (tagType() == MetaTagType.FLOAT) {
                this.floatValue = _io.readF4le();
            }
            if (tagType() == MetaTagType.LONG_STR) {
                this.longStrSize = _io.readU4le();
            }
            if (tagType() == MetaTagType.LONG_STR) {
                this.longStrValue = _io.readStrByteLimit(longStrSize(), "UTF-8");
            }
            if (tagType() == MetaTagType.UINT16) {
                this.uint16Value = _io.readU2le();
            }
            if (tagType() == MetaTagType.BYTE) {
                this.byteValue = _io.readU1();
            }
            if (tagType() == MetaTagType.UINT64) {
                this.uint64Value = _io.readU8le();
            }
        }
        private MetaTagType tagType;
        private byte[] nameLength;
        private int tagNumber;
        private int strSize;
        private String strValue;
        private long intValue;
        private float floatValue;
        private long longStrSize;
        private String longStrValue;
        private int uint16Value;
        private int byteValue;
        private long uint64Value;
        private KnownMet _root;
        private KnownMet.Entry _parent;
        public MetaTagType tagType() { return tagType; }
        public byte[] nameLength() { return nameLength; }
        public int tagNumber() { return tagNumber; }
        public int strSize() { return strSize; }
        public String strValue() { return strValue; }
        public long intValue() { return intValue; }
        public float floatValue() { return floatValue; }
        public long longStrSize() { return longStrSize; }
        public String longStrValue() { return longStrValue; }
        public int uint16Value() { return uint16Value; }
        public int byteValue() { return byteValue; }
        public long uint64Value() { return uint64Value; }
        public KnownMet _root() { return _root; }
        public KnownMet.Entry _parent() { return _parent; }
    }
    private byte[] magic;
    private long nEntries;
    private ArrayList<Entry> entries;
    private KnownMet _root;
    private KaitaiStruct _parent;
    public byte[] magic() { return magic; }
    public long nEntries() { return nEntries; }
    public ArrayList<Entry> entries() { return entries; }
    public KnownMet _root() { return _root; }
    public KaitaiStruct _parent() { return _parent; }

    public enum MetaTagType {
        BYTE(9),
        STRING(2),
        LONG_STR(7),
        INTEGER(3),
        UINT64(11),
        UINT16(8),
        FLOAT(4);

        private final long id;
        MetaTagType(long id) { this.id = id; }
        public long id() { return id; }
        private static final Map<Long, MetaTagType> byId = new HashMap<Long, MetaTagType>(7);
        static {
            for (MetaTagType e : MetaTagType.values())
                byId.put(e.id(), e);
        }
        public static MetaTagType byId(long id) { return byId.get(id); }
    }
}
