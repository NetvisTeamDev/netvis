//go:build windows

// Package winicon extracts a small icon for a given executable path and
// encodes it as PNG bytes, for display in the UI. Uses raw Win32 syscalls
// (SHGetFileInfoW + GetIconInfo + GetDIBits) rather than a third-party
// dependency, consistent with the rest of netvis.
package winicon

import (
	"bytes"
	"fmt"
	"image"
	"image/png"
	"syscall"
	"unsafe"
)

const (
	shgfiIcon      = 0x000000100
	shgfiSmallIcon = 0x000000001

	biRGB        = 0
	dibRGBColors = 0
)

var (
	shell32 = syscall.NewLazyDLL("shell32.dll")
	user32  = syscall.NewLazyDLL("user32.dll")
	gdi32   = syscall.NewLazyDLL("gdi32.dll")

	procSHGetFileInfoW = shell32.NewProc("SHGetFileInfoW")
	procGetIconInfo    = user32.NewProc("GetIconInfo")
	procDestroyIcon    = user32.NewProc("DestroyIcon")
	procGetDC          = user32.NewProc("GetDC")
	procReleaseDC      = user32.NewProc("ReleaseDC")

	procGetObject = gdi32.NewProc("GetObjectW")
	procGetDIBits = gdi32.NewProc("GetDIBits")
	procDeleteObj = gdi32.NewProc("DeleteObject")
)

type shfileinfoW struct {
	hIcon         syscall.Handle
	iIcon         int32
	dwAttributes  uint32
	szDisplayName [260]uint16
	szTypeName    [80]uint16
}

type iconInfo struct {
	fIcon    int32
	xHotspot uint32
	yHotspot uint32
	hbmMask  syscall.Handle
	hbmColor syscall.Handle
}

type bitmap struct {
	bmType       int32
	bmWidth      int32
	bmHeight     int32
	bmWidthBytes int32
	bmPlanes     uint16
	bmBitsPixel  uint16
	bmBits       uintptr
}

type bitmapInfoHeader struct {
	biSize          uint32
	biWidth         int32
	biHeight        int32
	biPlanes        uint16
	biBitCount      uint16
	biCompression   uint32
	biSizeImage     uint32
	biXPelsPerMeter int32
	biYPelsPerMeter int32
	biClrUsed       uint32
	biClrImportant  uint32
}

// ExtractPNG returns a small (typically 16x16) icon for the given
// executable path, encoded as PNG bytes.
func ExtractPNG(path string) ([]byte, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	var sfi shfileinfoW
	ret, _, _ := procSHGetFileInfoW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		uintptr(unsafe.Pointer(&sfi)),
		unsafe.Sizeof(sfi),
		uintptr(shgfiIcon|shgfiSmallIcon),
	)
	if ret == 0 || sfi.hIcon == 0 {
		return nil, fmt.Errorf("SHGetFileInfoW: no icon for %s", path)
	}
	defer procDestroyIcon.Call(uintptr(sfi.hIcon))

	var info iconInfo
	ret, _, _ = procGetIconInfo.Call(uintptr(sfi.hIcon), uintptr(unsafe.Pointer(&info)))
	if ret == 0 {
		return nil, fmt.Errorf("GetIconInfo failed for %s", path)
	}
	if info.hbmColor != 0 {
		defer procDeleteObj.Call(uintptr(info.hbmColor))
	}
	if info.hbmMask != 0 {
		defer procDeleteObj.Call(uintptr(info.hbmMask))
	}
	if info.hbmColor == 0 {
		return nil, fmt.Errorf("icon for %s has no color bitmap", path)
	}

	var bm bitmap
	procGetObject.Call(uintptr(info.hbmColor), unsafe.Sizeof(bm), uintptr(unsafe.Pointer(&bm)))
	if bm.bmWidth == 0 || bm.bmHeight == 0 {
		return nil, fmt.Errorf("icon for %s has zero size", path)
	}
	w, h := int(bm.bmWidth), int(bm.bmHeight)

	hdc, _, _ := procGetDC.Call(0)
	if hdc == 0 {
		return nil, fmt.Errorf("GetDC failed")
	}
	defer procReleaseDC.Call(0, hdc)

	bmi := bitmapInfoHeader{
		biWidth:       int32(w),
		biHeight:      int32(-h), // negative: top-down DIB, row 0 = top row
		biPlanes:      1,
		biBitCount:    32,
		biCompression: biRGB,
	}
	bmi.biSize = uint32(unsafe.Sizeof(bmi))

	pixels := make([]byte, w*h*4)
	ret, _, _ = procGetDIBits.Call(
		hdc,
		uintptr(info.hbmColor),
		0,
		uintptr(h),
		uintptr(unsafe.Pointer(&pixels[0])),
		uintptr(unsafe.Pointer(&bmi)),
		dibRGBColors,
	)
	if ret == 0 {
		return nil, fmt.Errorf("GetDIBits failed for %s", path)
	}

	// DIB pixel order is BGRA; image.RGBA wants RGBA.
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	hasAlpha := false
	for i := 0; i < w*h; i++ {
		b := pixels[i*4+0]
		g := pixels[i*4+1]
		r := pixels[i*4+2]
		a := pixels[i*4+3]
		if a != 0 {
			hasAlpha = true
		}
		img.Pix[i*4+0] = r
		img.Pix[i*4+1] = g
		img.Pix[i*4+2] = b
		img.Pix[i*4+3] = a
	}
	if !hasAlpha {
		// Older-style icon with no real alpha channel in the color
		// bitmap - treat as fully opaque rather than rendering nothing.
		for i := 0; i < w*h; i++ {
			img.Pix[i*4+3] = 255
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
