package utils

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type CRYPT_DATA_BLOB struct {
	CbData uint32
	PbData *byte
}

type CERT_NAME_BLOB = CRYPT_DATA_BLOB
type CRYPT_INTEGER_BLOB = CRYPT_DATA_BLOB
type CRYPT_OBJID_BLOB = CRYPT_DATA_BLOB

type CRYPT_ALGORITHM_IDENTIFIER struct {
	pszObjId   *byte
	Parameters CRYPT_OBJID_BLOB
}

type CRYPT_ATTRIBUTE struct {
	pszObjId *byte
	cValue   uint32
	rgValue  *CRYPT_DATA_BLOB
}

type CRYPT_ATTRIBUTES struct {
	cAttr  uint32
	rgAttr *CRYPT_ATTRIBUTE
}

type CRYPT_BIT_BLOB struct {
	CbData      uint32
	PbData      *byte
	CUnusedBits uint32
}

type CERT_PUBLIC_KEY_INFO struct {
	Algorithm CRYPT_ALGORITHM_IDENTIFIER
	PublicKey CRYPT_BIT_BLOB
}

type CERT_EXTENSION struct {
	pszObjId  *byte
	fCritical int32 //BOOL
	Value     CRYPT_DATA_BLOB
}

// CMSG_SIGNER_INFO
type CMSG_SIGNER_INFO struct {
	DwVersion               uint32
	Issuer                  CERT_NAME_BLOB
	SerialNumber            CRYPT_INTEGER_BLOB
	HashAlgorithm           CRYPT_ALGORITHM_IDENTIFIER
	HashEncryptionAlgorithm CRYPT_ALGORITHM_IDENTIFIER
	EncryptedHash           CRYPT_DATA_BLOB
	AuthAttrs               CRYPT_ATTRIBUTES
	UnauthAttrs             CRYPT_ATTRIBUTES
}

// CERT_INFO
type CERT_INFO struct {
	DwVersion            uint32
	SerialNumber         CRYPT_INTEGER_BLOB
	SignatureAlgorithm   CRYPT_ALGORITHM_IDENTIFIER
	Issuer               CERT_NAME_BLOB
	NotBefore            syscall.Filetime
	NotAfter             syscall.Filetime
	Subject              CERT_NAME_BLOB
	SubjectPublicKeyInfo CERT_PUBLIC_KEY_INFO
	IssuerUniqueId       CRYPT_BIT_BLOB
	SubjectUniqueId      CRYPT_BIT_BLOB
	CExtension           uint32
	RgExtension          *CERT_EXTENSION
}

type HCERTSTORE uintptr
type HCRYPTMSG uintptr
type PCCERT_CONTEXT uintptr

const (
	CERT_QUERY_OBJECT_FILE = 1

	CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED = 10
	CERT_QUERY_FORMAT_BINARY              = 1

	//flag必须是1<<10=0x400
	CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1 << CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED
	CERT_QUERY_FORMAT_FLAG_BINARY              = 1 << CERT_QUERY_FORMAT_BINARY

	CMSG_SIGNER_INFO_PARAM = 6

	CERT_FIND_SUBJECT_CERT = 0x000B0000

	CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
	//如果想要颁发者名字可以用这个 flag
	CERT_NAME_ISSUER_FLAG = 0x1
)

var (
	modCrypt32 = syscall.NewLazyDLL("crypt32.dll")

	// NT路径缓存
	ntPathCache     map[string]string
	ntPathCacheOnce sync.Once
	ntPathCacheMu   sync.RWMutex

	procCryptQueryObject           = modCrypt32.NewProc("CryptQueryObject")
	procCryptMsgGetParam           = modCrypt32.NewProc("CryptMsgGetParam")
	procCertFindCertificateInStore = modCrypt32.NewProc("CertFindCertificateInStore")
	procCertGetNameStringW         = modCrypt32.NewProc("CertGetNameStringW")
	procCertFreeCertificateContext = modCrypt32.NewProc("CertFreeCertificateContext")
	procCertCloseStore             = modCrypt32.NewProc("CertCloseStore")
	procCryptMsgClose              = modCrypt32.NewProc("CryptMsgClose")
)

// 获取签名
func GetSignName(path string) (string, error) {
	wPath, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}

	var (
		encoding   uint32
		contentTyp uint32
		formatTyp  uint32
		hStore     HCERTSTORE
		hMsg       HCRYPTMSG
	)

	r1, _, e1 := procCryptQueryObject.Call(
		uintptr(CERT_QUERY_OBJECT_FILE),
		uintptr(unsafe.Pointer(wPath)),
		uintptr(CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED),
		uintptr(CERT_QUERY_FORMAT_FLAG_BINARY),
		0,
		uintptr(unsafe.Pointer(&encoding)),
		uintptr(unsafe.Pointer(&contentTyp)),
		uintptr(unsafe.Pointer(&formatTyp)),
		uintptr(unsafe.Pointer(&hStore)),
		uintptr(unsafe.Pointer(&hMsg)),
		0,
	)
	if r1 == 0 {
		return "", fmt.Errorf("CryptQueryObject failed: %v", e1)
	}
	defer procCryptMsgClose.Call(uintptr(hMsg))
	defer procCertCloseStore.Call(uintptr(hStore), 0)

	var signerInfoLen uint32
	r1, _, e1 = procCryptMsgGetParam.Call(
		uintptr(hMsg),
		uintptr(CMSG_SIGNER_INFO_PARAM),
		0,
		0,
		uintptr(unsafe.Pointer(&signerInfoLen)),
	)
	if r1 == 0 {
		return "", fmt.Errorf("CryptMsgGetParam(size) failed: %v", e1)
	}

	buf := make([]byte, signerInfoLen)
	r1, _, e1 = procCryptMsgGetParam.Call(
		uintptr(hMsg),
		uintptr(CMSG_SIGNER_INFO_PARAM),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&signerInfoLen)),
	)
	if r1 == 0 {
		return "", fmt.Errorf("CryptMsgGetParam(data) failed: %v", e1)
	}

	pSignerInfo := (*CMSG_SIGNER_INFO)(unsafe.Pointer(&buf[0]))

	var certInfo CERT_INFO
	certInfo.Issuer = pSignerInfo.Issuer
	certInfo.SerialNumber = pSignerInfo.SerialNumber

	r1, _, e1 = procCertFindCertificateInStore.Call(
		uintptr(hStore),
		uintptr(encoding),
		0,
		uintptr(CERT_FIND_SUBJECT_CERT),
		uintptr(unsafe.Pointer(&certInfo)),
		0,
	)
	if r1 == 0 {
		return "", fmt.Errorf("CertFindCertificateInStore failed: %v", e1)
	}
	pCertContext := PCCERT_CONTEXT(r1)
	defer procCertFreeCertificateContext.Call(uintptr(pCertContext))

	nameLen, _, e1 := procCertGetNameStringW.Call(
		uintptr(pCertContext),
		uintptr(CERT_NAME_SIMPLE_DISPLAY_TYPE),
		0,
		0,
		0,
		0,
	)
	if nameLen <= 1 {
		return "", fmt.Errorf("CertGetNameStringW(size) failed: %v", e1)
	}

	nameBuf := make([]uint16, nameLen)
	r1, _, e1 = procCertGetNameStringW.Call(
		uintptr(pCertContext),
		uintptr(CERT_NAME_SIMPLE_DISPLAY_TYPE),
		0,
		0,
		uintptr(unsafe.Pointer(&nameBuf[0])),
		nameLen,
	)
	if r1 <= 1 {
		return "", fmt.Errorf("CertGetNameStringW(data) failed: %v", e1)
	}

	return syscall.UTF16ToString(nameBuf), nil
}

// 结束进程
func Kill(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("无效 PID: %d", pid)
	}

	var errs []error

	if err := killOS(pid); err == nil {
		return nil
	} else {
		errs = append(errs, fmt.Errorf("os.Kill 失败: %w", err))
	}

	if err := killAPI(pid); err == nil {
		return nil
	} else {
		errs = append(errs, fmt.Errorf("WinAPI TerminateProcess 失败: %w", err))
	}

	msg := "失败:\n"
	for _, e := range errs {
		msg += "  - " + e.Error() + "\n"
	}
	return fmt.Errorf(msg)
}

func killOS(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}

func killCmd(pid int) error {
	cmd := exec.Command("taskkill", "/PID", strconv.Itoa(pid), "/F", "/T")

	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cmd 执行错误: %v, 输出: %s", err, string(out))
	}
	return nil
}

func killAPI(pid int) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("OpenProcess 失败: %w", err)
	}
	defer windows.CloseHandle(h)

	if err = windows.TerminateProcess(h, 1); err != nil {
		return fmt.Errorf("TerminateProcess 失败: %w", err)
	}
	return nil
}

// 枚举进程
func Listpid() []uint32 {
	h, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(h)

	var out []uint32
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err = windows.Process32First(h, &entry); err != nil {
		return nil
	}
	for {
		out = append(out, entry.ProcessID)
		if err = windows.Process32Next(h, &entry); err != nil {
			break
		}
	}
	return out
}

// 缓存 NT 路径与常规win路径的映射
func NTPathC() {
	ntPathCacheOnce.Do(func() {
		cache := make(map[string]string)

		buf := make([]uint16, 254)
		n, err := windows.GetLogicalDriveStrings(uint32(len(buf)), &buf[0])
		if err != nil || n == 0 {
			ntPathCacheMu.Lock()
			ntPathCache = cache
			ntPathCacheMu.Unlock()
			return
		}

		drives := strings.Split(strings.TrimRight(windows.UTF16ToString(buf[:n]), "\x00"), "\x00")
		for _, drive := range drives {
			d := strings.TrimSuffix(drive, "\\")
			if d == "" {
				continue
			}

			var devBuf [1024]uint16
			if m, err := windows.QueryDosDevice(syscall.StringToUTF16Ptr(d), &devBuf[0], uint32(len(devBuf))); err == nil && m > 0 {
				device := windows.UTF16ToString(devBuf[:m])
				if device != "" {
					cache[strings.ToLower(device)] = d + "\\"
				}
			}
		}

		ntPathCacheMu.Lock()
		ntPathCache = cache
		ntPathCacheMu.Unlock()
	})
}

// 将NT路径转换为win路径，失败就返回原路径
func NToWin(ntPath string) string {
	if ntPath == "" {
		return ntPath
	}

	if strings.Contains(ntPath, ":\\") {
		return ntPath
	}

	NTPathC()

	ntPathLower := strings.ToLower(ntPath)
	ntPathCacheMu.RLock()
	defer ntPathCacheMu.RUnlock()

	var (
		matchedDev   string
		matchedDrive string
	)

	for dev, drive := range ntPathCache {
		if strings.HasPrefix(ntPathLower, dev) && len(dev) > len(matchedDev) {
			matchedDev = dev
			matchedDrive = drive
		}
	}

	if matchedDev == "" {
		return ntPath
	}

	suffix := strings.TrimPrefix(ntPath[len(matchedDev):], "\\")
	if strings.HasSuffix(matchedDrive, "\\") {
		return matchedDrive + suffix
	}
	return matchedDrive + "\\" + suffix
}
