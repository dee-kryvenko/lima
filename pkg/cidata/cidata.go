package cidata

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lima-vm/lima/pkg/downloader"
	"github.com/lima-vm/lima/pkg/iso9660util"
	"github.com/lima-vm/lima/pkg/limayaml"
	"github.com/lima-vm/lima/pkg/localpathutil"
	"github.com/lima-vm/lima/pkg/osutil"
	qemu "github.com/lima-vm/lima/pkg/qemu/const"
	"github.com/lima-vm/lima/pkg/sshutil"
	"github.com/lima-vm/lima/pkg/store/filenames"
	"github.com/sirupsen/logrus"
)

func setupEnv(y *limayaml.LimaYAML) (map[string]string, error) {
	// Start with the proxy variables from the system settings.
	env, err := osutil.ProxySettings()
	if err != nil {
		return env, err
	}
	// env.* settings from lima.yaml override system settings without giving a warning
	for name, value := range y.Env {
		env[name] = value
	}
	// Current process environment setting override both system settings and env.*
	lowerVars := []string{"ftp_proxy", "http_proxy", "https_proxy", "no_proxy"}
	upperVars := make([]string, len(lowerVars))
	for i, name := range lowerVars {
		upperVars[i] = strings.ToUpper(name)
	}
	for _, name := range append(lowerVars, upperVars...) {
		if value, ok := os.LookupEnv(name); ok {
			if _, ok := env[name]; ok && value != env[name] {
				logrus.Infof("Overriding %q value %q with %q from limactl process environment",
					name, env[name], value)
			}
			env[name] = value
		}
	}
	// Make sure uppercase variants have the same value as lowercase ones.
	// If both are set, the lowercase variant value takes precedence.
	for _, lowerName := range lowerVars {
		upperName := strings.ToUpper(lowerName)
		if _, ok := env[lowerName]; ok {
			if _, ok := env[upperName]; ok && env[lowerName] != env[upperName] {
				logrus.Warnf("Changing %q value from %q to %q to match %q",
					upperName, env[upperName], env[lowerName], lowerName)
			}
			env[upperName] = env[lowerName]
		} else if _, ok := env[upperName]; ok {
			env[lowerName] = env[upperName]
		}
	}
	return env, nil
}

func GenerateISO9660(instDir, name string, y *limayaml.LimaYAML, udpDNSLocalPort, tcpDNSLocalPort int) error {
	if err := limayaml.Validate(*y, false); err != nil {
		return err
	}
	u, err := osutil.LimaUser(true)
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	args := TemplateArgs{
		Name:         name,
		User:         u.Username,
		UID:          uid,
		Containerd:   Containerd{System: *y.Containerd.System, User: *y.Containerd.User},
		SlirpNICName: qemu.SlirpNICName,
		SlirpGateway: qemu.SlirpGateway,
		SlirpDNS:     qemu.SlirpDNS,
	}

	// change instance id on every boot so network config will be processed again
	args.IID = fmt.Sprintf("iid-%d", time.Now().Unix())

	pubKeys, err := sshutil.DefaultPubKeys(*y.SSH.LoadDotSSHPubKeys)
	if err != nil {
		return err
	}
	if len(pubKeys) == 0 {
		return errors.New("no SSH key was found, run `ssh-keygen`")
	}
	for _, f := range pubKeys {
		args.SSHPubKeys = append(args.SSHPubKeys, f.Content)
	}

	for _, f := range y.Mounts {
		expanded, err := localpathutil.Expand(f.Location)
		if err != nil {
			return err
		}
		args.Mounts = append(args.Mounts, expanded)
	}

	slirpMACAddress := limayaml.MACAddress(instDir)
	args.Networks = append(args.Networks, Network{MACAddress: slirpMACAddress, Interface: qemu.SlirpNICName})
	for _, nw := range y.Networks {
		args.Networks = append(args.Networks, Network{MACAddress: nw.MACAddress, Interface: nw.Interface})
	}

	args.Env, err = setupEnv(y)
	if err != nil {
		return err
	}
	if *y.UseHostResolver {
		args.UDPDNSLocalPort = udpDNSLocalPort
		args.TCPDNSLocalPort = tcpDNSLocalPort
		args.DNSAddresses = append(args.DNSAddresses, qemu.SlirpDNS)
	} else if len(y.DNS) > 0 {
		for _, addr := range y.DNS {
			args.DNSAddresses = append(args.DNSAddresses, addr.String())
		}
	} else {
		args.DNSAddresses, err = osutil.DNSAddresses()
		if err != nil {
			return err
		}
	}

	if err := ValidateTemplateArgs(args); err != nil {
		return err
	}

	layout, err := ExecuteTemplate(args)
	if err != nil {
		return err
	}

	for i, f := range y.Provision {
		switch f.Mode {
		case limayaml.ProvisionModeSystem, limayaml.ProvisionModeUser:
			layout = append(layout, iso9660util.Entry{
				Path:   fmt.Sprintf("provision.%s/%08d", f.Mode, i),
				Reader: strings.NewReader(f.Script),
			})
		default:
			return fmt.Errorf("unknown provision mode %q", f.Mode)
		}
	}

	if guestAgentBinary, err := GuestAgentBinary(y.Arch); err != nil {
		return err
	} else {
		defer guestAgentBinary.Close()
		layout = append(layout, iso9660util.Entry{
			Path:   "lima-guestagent",
			Reader: guestAgentBinary,
		})
	}

	if args.Containerd.System || args.Containerd.User {
		var nftgz *limayaml.File
		for i := range y.Containerd.Archives {
			f := &y.Containerd.Archives[i]
			if f.Arch != y.Arch {
				continue
			}
			nftgz = f
		}
		if nftgz == nil {
			return fmt.Errorf("no containerd archive was provided for arch %q", y.Arch)
		}
		td, err := ioutil.TempDir("", "lima-download-nerdctl")
		if err != nil {
			return err
		}
		defer os.RemoveAll(td)
		nftgzLocal := filepath.Join(td, "nerdctl-full.tgz")
		logrus.Infof("Downloading %q (%s)", nftgz.Location, nftgz.Digest)
		res, err := downloader.Download(nftgzLocal, nftgz.Location, downloader.WithCache(), downloader.WithExpectedDigest(nftgz.Digest))
		if err != nil {
			return fmt.Errorf("failed to download %q: %w", nftgz.Location, err)
		}
		logrus.Debugf("res.ValidatedDigest=%v", res.ValidatedDigest)
		switch res.Status {
		case downloader.StatusDownloaded:
			logrus.Infof("Downloaded %q", nftgz.Location)
		case downloader.StatusUsedCache:
			logrus.Infof("Using cache %q", res.CachePath)
		default:
			logrus.Warnf("Unexpected result from downloader.Download(): %+v", res)
		}

		nftgzR, err := os.Open(nftgzLocal)
		if err != nil {
			return err
		}
		defer nftgzR.Close()
		layout = append(layout, iso9660util.Entry{
			// ISO9660 requires len(Path) <= 30
			Path:   "nerdctl-full.tgz",
			Reader: nftgzR,
		})
	}

	return iso9660util.Write(filepath.Join(instDir, filenames.CIDataISO), "cidata", layout)
}

func GuestAgentBinary(arch string) (io.ReadCloser, error) {
	if arch == "" {
		return nil, errors.New("arch must be set")
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	selfSt, err := os.Stat(self)
	if err != nil {
		return nil, err
	}
	if selfSt.Mode()&fs.ModeSymlink != 0 {
		self, err = os.Readlink(self)
		if err != nil {
			return nil, err
		}
	}

	// self:  /usr/local/bin/limactl
	selfDir := filepath.Dir(self)
	selfDirDir := filepath.Dir(selfDir)
	candidates := []string{
		// candidate 0:
		// - self:  /Applications/Lima.app/Contents/MacOS/limactl
		// - agent: /Applications/Lima.app/Contents/MacOS/lima-guestagent.Linux-x86_64
		filepath.Join(selfDir, "lima-guestagent.Linux-"+arch),
		// candidate 1:
		// - self:  /usr/local/bin/limactl
		// - agent: /usr/local/share/lima/lima-guestagent.Linux-x86_64
		filepath.Join(selfDirDir, "share/lima/lima-guestagent.Linux-"+arch),
		// TODO: support custom path
	}
	for _, candidate := range candidates {
		if f, err := os.Open(candidate); err == nil {
			return f, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}

	return nil, fmt.Errorf("failed to find \"lima-guestagent.Linux-%s\" binary for %q, attempted %v",
		arch, self, candidates)
}
