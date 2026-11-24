// SPDX-License-Identifier: AGPL-3.0-only

package matrix

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"html"
	"image"
	"image/color"
	"image/jpeg"
	"strings"

	fp "github.com/heliopsy/scrim/internal/testing/fakeprovider"
)

// attachment builds a request whose user message carries data as a binary
// content part of mediaType: the way an agent attaches a screenshot, a PDF or
// a file. Images go in each API's image part, anything else in its document
// or file part.
func attachment(api fp.API, mediaType string, data []byte, mode Escape) []Request {
	b64 := base64.StdEncoding.EncodeToString(data)
	dataURL := "data:" + mediaType + ";base64," + b64
	isImage := strings.HasPrefix(mediaType, "image/")
	const ask = "What does this attachment show?"
	switch api {
	case fp.Anthropic:
		kind := "document"
		if isImage {
			kind = "image"
		}
		part := obj("type", kind, "source", obj("type", "base64", "media_type", mediaType, "data", b64))
		return one(req(api, anthropicParts{messages: []any{obj("role", "user", "content", []any{part, obj("type", "text", "text", ask)})}}.body(), mode, false))
	case fp.OpenAIChat:
		part := obj("type", "file", "file", obj("filename", "attachment", "file_data", dataURL))
		if isImage {
			part = obj("type", "image_url", "image_url", obj("url", dataURL))
		}
		return one(req(api, chatParts{messages: []any{obj("role", "user", "content", []any{part, obj("type", "text", "text", ask)})}}.body(), mode, false))
	case fp.OpenAIResponses:
		part := obj("type", "input_file", "filename", "attachment", "file_data", dataURL)
		if isImage {
			part = obj("type", "input_image", "image_url", dataURL)
		}
		return one(req(api, responsesParts{input: []any{obj("type", "message", "role", "user", "content", []any{part, obj("type", "input_text", "text", ask)})}}.body(), mode, false))
	case fp.Gemini:
		part := obj("inlineData", obj("mimeType", mediaType, "data", b64))
		return one(req(api, geminiParts{contents: []any{obj("role", "user", "parts", []any{part, obj("text", ask)})}}.body(), mode, false))
	}
	return nil
}

// pngChunk appends one PNG chunk with its CRC.
func pngChunk(b *bytes.Buffer, typ string, data []byte) {
	_ = binary.Write(b, binary.BigEndian, uint32(len(data))) //nolint:gosec // test fixtures are small
	b.WriteString(typ)
	b.Write(data)
	crc := crc32.NewIEEE()
	crc.Write([]byte(typ))
	crc.Write(data)
	_ = binary.Write(b, binary.BigEndian, crc.Sum32())
}

func zlibBytes(data []byte) []byte {
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	_, _ = w.Write(data)
	_ = w.Close()
	return b.Bytes()
}

// pngWithText returns a 1x1 PNG whose tEXt chunk carries text, the way an
// image's metadata can carry a secret into a screenshot.
func pngWithText(key, text string) []byte {
	var b bytes.Buffer
	b.WriteString("\x89PNG\r\n\x1a\n")
	pngChunk(&b, "IHDR", []byte{0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0})
	pngChunk(&b, "tEXt", append([]byte(key+"\x00"), text...))
	pngChunk(&b, "IDAT", zlibBytes([]byte{0, 0}))
	pngChunk(&b, "IEND", nil)
	return b.Bytes()
}

// pngWithZText returns a 1x1 PNG whose compressed zTXt chunk carries text.
func pngWithZText(key, text string) []byte {
	var b bytes.Buffer
	b.WriteString("\x89PNG\r\n\x1a\n")
	pngChunk(&b, "IHDR", []byte{0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0})
	pngChunk(&b, "zTXt", append([]byte(key+"\x00\x00"), zlibBytes([]byte(text))...))
	pngChunk(&b, "IDAT", zlibBytes([]byte{0, 0}))
	pngChunk(&b, "IEND", nil)
	return b.Bytes()
}

// pngWithPixels returns a one-row 8-bit greyscale PNG whose pixel values are
// the bytes of text: the secret is in the image data, as rendered text in a
// screenshot is, and only decoding the pixels would find it.
func pngWithPixels(text string) []byte {
	var b bytes.Buffer
	b.WriteString("\x89PNG\r\n\x1a\n")
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:], uint32(max(len(text), 1))) //nolint:gosec // test fixtures are small
	binary.BigEndian.PutUint32(ihdr[4:], 1)
	ihdr[8] = 8 // bit depth; colour type 0 (greyscale)
	pngChunk(&b, "IHDR", ihdr)
	pngChunk(&b, "IDAT", zlibBytes(append([]byte{0}, text...)))
	pngChunk(&b, "IEND", nil)
	return b.Bytes()
}

// jpegWithComment returns a real 8x8 JPEG with a COM segment carrying text
// right after SOI, where cameras and editors put comments.
func jpegWithComment(text string) []byte {
	img := image.NewGray(image.Rect(0, 0, 8, 8))
	for i := range img.Pix {
		img.Pix[i] = color.Gray{Y: uint8(i * 4)}.Y //nolint:gosec // 0..252
	}
	var enc bytes.Buffer
	_ = jpeg.Encode(&enc, img, nil)
	src := enc.Bytes()
	var b bytes.Buffer
	b.Write(src[:2]) // SOI
	// A COM segment holds at most 65533 bytes; longer text is split over
	// several, as a writer would.
	for rest := []byte(text); ; {
		n := min(len(rest), 65533)
		b.Write([]byte{0xff, 0xfe})
		_ = binary.Write(&b, binary.BigEndian, uint16(n+2)) //nolint:gosec // bounded above
		b.Write(rest[:n])
		rest = rest[n:]
		if len(rest) == 0 {
			break
		}
	}
	b.Write(src[2:])
	return b.Bytes()
}

// svgWithText returns an SVG image drawing text.
func svgWithText(text string) []byte {
	return []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="400" height="40"><text x="4" y="24">` +
		html.EscapeString(text) + `</text></svg>`)
}

// pdfWithText returns a one-page PDF whose Flate-compressed content stream
// shows text. The string is a literal unless it holds characters a literal
// would escape, then a hex string, both as PDF writers produce them.
func pdfWithText(text string) []byte {
	str := "(" + text + ")"
	if strings.ContainsAny(text, "()\\\r") {
		str = fmt.Sprintf("<%X>", text)
	}
	content := zlibBytes([]byte("BT /F1 12 Tf 72 712 Td " + str + " Tj ET\n"))
	var b bytes.Buffer
	var offsets []int
	addObj := func(body string, stream []byte) {
		offsets = append(offsets, b.Len())
		fmt.Fprintf(&b, "%d 0 obj\n%s", len(offsets), body)
		if stream != nil {
			b.WriteString("\nstream\n")
			b.Write(stream)
			b.WriteString("\nendstream")
		}
		b.WriteString("\nendobj\n")
	}
	b.WriteString("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
	addObj("<< /Type /Catalog /Pages 2 0 R >>", nil)
	addObj("<< /Type /Pages /Kids [3 0 R] /Count 1 >>", nil)
	addObj("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>", nil)
	addObj(fmt.Sprintf("<< /Length %d /Filter /FlateDecode >>", len(content)), content)
	addObj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>", nil)
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(offsets)+1)
	for _, o := range offsets {
		fmt.Fprintf(&b, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offsets)+1, xref)
	return b.Bytes()
}
