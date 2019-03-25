// Read a generic "framed" packet consisting of a header and a
// This is used for both TLS Records and TLS Handshake Messages
package mint

import "fmt"

type framing interface {
	headerLen() int
	defaultReadLen() int
	frameLen(hdr []byte) (int, int, error)
}

const (
	kFrameReaderHdr  = 0
	kFrameReaderBody = 1
)

type frameNextAction func(f *frameReader) error

type frameReader struct {
	details     framing
	state       uint8
	header      []byte
	body        []byte
	working     []byte
	writeOffset int
	remainder   []byte
}

func newFrameReader(d framing) *frameReader {
	hdr := make([]byte, d.headerLen())
	return &frameReader {
		d,
		kFrameReaderHdr,
		hdr,
		nil,
		hdr,
		0,
		nil,
	}
}

func dup(a []byte) []byte {
	r := make([]byte, len(a))
	copy(r, a)
	return r
}

func (f *frameReader) needed() int {
	logf(logTypeFrameReader, "Needed %d %d %d", len(f.working), f.writeOffset, len(f.remainder))
	tmp := (len(f.working) - f.writeOffset) - len(f.remainder)
	if tmp < 0 {
		return 0
	}
	return tmp
}

func (f *frameReader) addChunk(in []byte) {
	// Append to the buffer.
	logf(logTypeFrameReader, "Appending %v", len(in))
	f.remainder = append(f.remainder, in...)
}

func (f *frameReader) process() (hdr []byte, body []byte, err error) {
	for f.needed() == 0 {
		logf(logTypeFrameReader, "%v bytes needed for next block", len(f.working)-f.writeOffset)

		logf(logTypeFrameReader, "Working %x %x", f.working, f.remainder)
		// Fill out our working block
		copied := copy(f.working[f.writeOffset:], f.remainder)
		f.remainder = f.remainder[copied:]
		f.writeOffset += copied
		if f.writeOffset < len(f.working) {
			logf(logTypeVerbose, "Read would have blocked 1")
			return nil, nil, AlertWouldBlock
		}
		// Reset the write offset, because we are now full.
		f.writeOffset = 0

		// We have read a full frame
		if f.state == kFrameReaderBody {
			logf(logTypeFrameReader, "Returning frame hdr=%#x body=%#x len=%d buffered=%d", f.header, f.body, len(f.body), len(f.remainder))
			f.state = kFrameReaderHdr
			f.working = f.header
			return dup(f.header), dup(f.body), nil
		}

		// We have read the header
		bodyLen, shift, err := f.details.frameLen(f.header)
		// bodyLen = bodyLen + shift

		// Determine if the header also carried part of the body
		var prefix []byte
		var header []byte
		var needsAdjustment bool
		if shift > 0 && shift <= len(f.header) {
			needsAdjustment = true
			prefix = f.working[shift:]
			header = f.header[0:shift]

			// panic(fmt.Sprintf("Body length %x %d", f.header, bodyLen))
			f.header = header
		}

		if err != nil {
			return nil, nil, err
		}
		logf(logTypeFrameReader, "Processed header, body len = %v", bodyLen)

		f.body = make([]byte, bodyLen)
		if needsAdjustment {
			// panic(fmt.Sprintf("Current state %x %x %x %x %x %d %d %d %d %d", f.header, f.working, f.remainder, header, prefix, f.writeOffset, len(f.body), len(f.header), len(prefix), len(f.working)))
			fmt.Printf("prepending %x", header)
			logf(logTypeFrameReader, "Prepending %d %d %x", len(prefix), len(f.body), prefix)
			f.body = append(prefix, f.body...)
			f.body = f.body[0:len(f.body) - len(prefix)]
			logf(logTypeFrameReader, "New body %x", f.body)
		}

		// panic(fmt.Sprintf("Adjusted body %x", f.body))
		f.working = f.body
		f.writeOffset = len(prefix)
		f.state = kFrameReaderBody
	}

	logf(logTypeVerbose, "Read would have blocked 2")
	return nil, nil, AlertWouldBlock
}
