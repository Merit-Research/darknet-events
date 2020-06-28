// Package seqjson implements a file writer that can write out an array of JSON
// objects sequentially and without requiring the entire array up-front.
package seqjson

import (
	"os"
	"sync"
)

// Writer implements a simple writer object in the same style as csv.Writer.
type Writer struct {
	f     *os.File
	first bool
	l     sync.Mutex
	newdl bool
}

// NewWriter returns a new Writer.
func NewWriter(file *os.File, newdl bool) *Writer {
	w := new(Writer)
	w.l.Lock()
	w.f = file
	w.first = true
	w.newdl = newdl

	if newdl == false {
		w.f.WriteString("[")
	}

	w.l.Unlock()
	return w
}

// Write writes a single json object to the end of the JSON array in the file.
func (w *Writer) Write(obj []byte) {
	w.l.Lock()

	if w.newdl == true && w.first == false {
		w.f.WriteString("\n")
	} else if w.newdl == false && w.first == false {
		w.f.WriteString(",\n")
	} else {
		w.first = false
	}

	w.f.Write(obj)
	w.l.Unlock()
}

// Close closes a Writer.
func (w *Writer) Close() {
	w.l.Lock()

	if w.newdl == false {
		w.f.WriteString("]")
	}
	w.l.Unlock()
}
